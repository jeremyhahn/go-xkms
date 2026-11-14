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

package mcp

import (
	"context"
	"crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestServer creates a server with initialized xkms for handler tests.
// It injects the XKMSService into Config so the server has full DI.
func createTestServer(t *testing.T) *Server {
	t.Helper()

	svc := setupTestXKMS(t)
	t.Cleanup(cleanupXKMS)

	server, err := NewServer(&Config{XKMSService: svc, Authenticator: auth.NewNoOpAuthenticator()})
	require.NoError(t, err)

	return server
}

// TestHandler_Health tests the health check handler
func TestHandler_Health(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	t.Run("returns healthy status", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "health",
			ID:      1,
		}

		result, err := server.handleHealth(context.Background(), req)
		require.NoError(t, err)

		healthResult, ok := result.(HealthResult)
		require.True(t, ok)
		assert.Equal(t, "healthy", healthResult.Status)
	})
}

// TestHandler_ContextPropagation verifies that a cancelled context is threaded
// through to handler invocations (F-10).  The health handler itself does not
// block on the context, but the test validates that passing a cancelled context
// does not cause a panic and that the handler function signature correctly
// accepts and passes the ctx parameter through the dispatch chain.
func TestHandler_ContextPropagation(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "health",
		Params:  json.RawMessage(`{}`),
		ID:      1,
	}

	// health is a pure function that does not inspect the context,
	// so it must return successfully even with a cancelled context.
	result, err := server.handleHealth(ctx, req)
	require.NoError(t, err)
	healthResult, ok := result.(HealthResult)
	require.True(t, ok)
	assert.Equal(t, "healthy", healthResult.Status)

	// InvokeMethod must also not panic when dispatching with a cancelled ctx.
	resp := invokeRequest(server, ctx, req)
	require.NotNil(t, resp)
	assert.Nil(t, resp.Error)
}

// TestHandler_GetBackend tests the xkms.getBackend handler added for
// go-xkms#762: docs/crypto-backends/api.md already documented this method as
// the MCP equivalent of REST's GET /api/v1/backends/{id}, but no handler
// existed to serve it.
func TestHandler_GetBackend(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	ctx := context.Background()

	t.Run("returns the named backend", func(t *testing.T) {
		params := GetBackendParams{Backend: "software"}
		paramsJSON, _ := json.Marshal(params)
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.getBackend", Params: paramsJSON, ID: 1}

		result, err := server.handleGetBackend(ctx, req)
		require.NoError(t, err)

		info, ok := result.(*transport.BackendInfo)
		require.True(t, ok)
		assert.Equal(t, "software", info.ID)
		assert.NotEmpty(t, info.Type)
	})

	t.Run("fails for an unknown backend", func(t *testing.T) {
		params := GetBackendParams{Backend: "does-not-exist"}
		paramsJSON, _ := json.Marshal(params)
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.getBackend", Params: paramsJSON, ID: 1}

		_, err := server.handleGetBackend(ctx, req)
		require.Error(t, err)
		assert.ErrorIs(t, err, xkms.ErrBackendNotFound)
	})

	t.Run("fails with an empty backend name as InvalidParams", func(t *testing.T) {
		paramsJSON, _ := json.Marshal(GetBackendParams{})
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.getBackend", Params: paramsJSON, ID: 1}

		_, err := server.handleGetBackend(ctx, req)
		require.Error(t, err)
		var keyOpErr *KeyOpError
		require.ErrorAs(t, err, &keyOpErr)
		assert.Equal(t, ErrCodeInvalidParams, keyOpErr.Code)
	})

	t.Run("fails with malformed JSON params as InvalidParams", func(t *testing.T) {
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.getBackend", Params: json.RawMessage(`{bad`), ID: 1}

		_, err := server.handleGetBackend(ctx, req)
		require.Error(t, err)
		var keyOpErr *KeyOpError
		require.ErrorAs(t, err, &keyOpErr)
		assert.Equal(t, ErrCodeInvalidParams, keyOpErr.Code)
	})
}

// TestHandler_GenerateKey tests the key generation handler
func TestHandler_GenerateKey(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	t.Run("generates RSA key", func(t *testing.T) {
		params := GenerateKeyParams{
			KeyID:   "test-rsa-key",
			Backend: "software",
			KeyType: "rsa", Algorithm: "rsa",
			KeySize: 2048,
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.generateKey",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleGenerateKey(context.Background(), req)
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
			KeyType: "ecdsa", Algorithm: "ecdsa",
			Curve: "P-256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.generateKey",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleGenerateKey(context.Background(), req)
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
			KeyType: "ed25519", Algorithm: "ed25519",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.generateKey",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleGenerateKey(context.Background(), req)
		require.NoError(t, err)

		genResult, ok := result.(GenerateKeyResult)
		require.True(t, ok)
		assert.Equal(t, "test-ed25519-key", genResult.KeyID)
		assert.NotEmpty(t, genResult.PublicKeyPEM)
	})

	t.Run("fails with missing key_id", func(t *testing.T) {
		params := GenerateKeyParams{
			Backend: "software",
			KeyType: "rsa", Algorithm: "rsa",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.generateKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleGenerateKey(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key_id is required")
	})

	t.Run("fails with invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.generateKey",
			Params:  json.RawMessage(`invalid json`),
			ID:      1,
		}

		_, err := server.handleGenerateKey(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})

	t.Run("fails with invalid backend", func(t *testing.T) {
		params := GenerateKeyParams{
			KeyID:   "test-key",
			Backend: "nonexistent",
			KeyType: "rsa", Algorithm: "rsa",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.generateKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleGenerateKey(context.Background(), req)
		require.Error(t, err)
		// An unregistered backend is now refused in the service layer's
		// vocabulary. The local gate this replaces went through
		// types.ParseStoreType, which also rejected every registered backend
		// name that is not itself a store type. The condition under test --
		// an unknown backend must not be served by the default one -- is
		// unchanged.
		assert.Contains(t, err.Error(), "backend not found")
	})

	t.Run("fails with unsupported key type", func(t *testing.T) {
		params := GenerateKeyParams{
			KeyID:   "test-key",
			Backend: "software",
			KeyType: "unsupported", Algorithm: "unsupported",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.generateKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleGenerateKey(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported key algorithm")
	})

	t.Run("generates key with default backend", func(t *testing.T) {
		params := GenerateKeyParams{
			KeyID:   "test-default-backend-key",
			KeyType: "rsa", Algorithm: "rsa",
			KeySize: 2048,
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.generateKey",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleGenerateKey(context.Background(), req)
		require.NoError(t, err)

		genResult, ok := result.(GenerateKeyResult)
		require.True(t, ok)
		assert.Equal(t, "test-default-backend-key", genResult.KeyID)
	})

	t.Run("generates ECDSA key with default curve", func(t *testing.T) {
		params := GenerateKeyParams{
			KeyID:   "test-ecdsa-default-curve",
			Backend: "software",
			KeyType: "ecdsa", Algorithm: "ecdsa",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.generateKey",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleGenerateKey(context.Background(), req)
		require.NoError(t, err)

		genResult, ok := result.(GenerateKeyResult)
		require.True(t, ok)
		assert.Equal(t, "test-ecdsa-default-curve", genResult.KeyID)
	})

	t.Run("fails with invalid curve", func(t *testing.T) {
		params := GenerateKeyParams{
			KeyID:   "test-invalid-curve",
			Backend: "software",
			KeyType: "ecdsa", Algorithm: "ecdsa",
			Curve: "invalid-curve",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.generateKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleGenerateKey(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid curve")
	})
}

// TestHandler_GetKey tests the get key handler
func TestHandler_GetKey(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	// First generate a key
	genParams := GenerateKeyParams{
		KeyID:   "test-get-key",
		Backend: "software",
		KeyType: "rsa", Algorithm: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(context.Background(), genReq)
	require.NoError(t, err)

	t.Run("gets existing key", func(t *testing.T) {
		params := GetKeyParams{
			KeyID:   "test-get-key",
			Backend: "software",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.getKey",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleGetKey(context.Background(), req)
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
			Method:  "xkms.getKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleGetKey(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key_id is required")
	})

	t.Run("fails with invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.getKey",
			Params:  json.RawMessage(`not json`),
			ID:      1,
		}

		_, err := server.handleGetKey(context.Background(), req)
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
			Method:  "xkms.getKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleGetKey(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key not found")
	})
}

// TestHandler_DeleteKey tests the delete key handler
func TestHandler_DeleteKey(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	// First generate a key
	genParams := GenerateKeyParams{
		KeyID:   "test-delete-key",
		Backend: "software",
		KeyType: "rsa", Algorithm: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(context.Background(), genReq)
	require.NoError(t, err)

	t.Run("deletes existing key", func(t *testing.T) {
		params := DeleteKeyParams{
			KeyID:   "test-delete-key",
			Backend: "software",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.deleteKey",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleDeleteKey(context.Background(), req)
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
			Method:  "xkms.deleteKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleDeleteKey(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key_id is required")
	})

	t.Run("fails with invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.deleteKey",
			Params:  json.RawMessage(`not json`),
			ID:      1,
		}

		_, err := server.handleDeleteKey(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})

	t.Run("deletes key without specifying backend", func(t *testing.T) {
		// Generate a key first
		genParams := GenerateKeyParams{
			KeyID:   "test-delete-no-backend",
			Backend: "software",
			KeyType: "rsa", Algorithm: "rsa",
			KeySize: 2048,
		}
		genParamsJSON, _ := json.Marshal(genParams)
		genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.generateKey", Params: genParamsJSON, ID: 1}
		_, err := server.handleGenerateKey(context.Background(), genReq)
		require.NoError(t, err)

		params := DeleteKeyParams{
			KeyID: "test-delete-no-backend",
			// No backend specified - should search
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.deleteKey",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleDeleteKey(context.Background(), req)
		require.NoError(t, err)

		deleteResult, ok := result.(map[string]interface{})
		require.True(t, ok)
		assert.True(t, deleteResult["success"].(bool))
	})
}

// TestHandler_RotateKey tests the rotate key handler
func TestHandler_RotateKey(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	// Generate initial key
	genParams := GenerateKeyParams{
		KeyID:   "test-rotate-key",
		Backend: "software",
		KeyType: "rsa", Algorithm: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.generateKey", Params: genParamsJSON, ID: 1}
	initialResult, err := server.handleGenerateKey(context.Background(), genReq)
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
			Method:  "xkms.rotateKey",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleRotateKey(context.Background(), req)
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
			Method:  "xkms.rotateKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleRotateKey(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key_id is required")
	})

	t.Run("fails with invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.rotateKey",
			Params:  json.RawMessage(`invalid`),
			ID:      1,
		}

		_, err := server.handleRotateKey(context.Background(), req)
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
			Method:  "xkms.rotateKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleRotateKey(context.Background(), req)
		require.Error(t, err)
		// An unregistered backend is now refused in the service layer's
		// vocabulary. The local gate this replaces went through
		// types.ParseStoreType, which also rejected every registered backend
		// name that is not itself a store type. The condition under test --
		// an unknown backend must not be served by the default one -- is
		// unchanged.
		assert.Contains(t, err.Error(), "backend not found")
	})
}

// TestHandler_Certificates tests the certificate handlers
func TestHandler_Certificates(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	// Generate a key first
	genParams := GenerateKeyParams{
		KeyID:   "test-cert-key",
		Backend: "software",
		KeyType: "rsa", Algorithm: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(context.Background(), genReq)
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
			Method:  "xkms.saveCert",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleSaveCert(context.Background(), req)
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
			Method:  "xkms.saveCert",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleSaveCert(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key_id is required")
	})

	t.Run("fails with missing cert_pem", func(t *testing.T) {
		params := SaveCertParams{KeyID: "test-cert-key"}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.saveCert",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleSaveCert(context.Background(), req)
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
			Method:  "xkms.saveCert",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleSaveCert(context.Background(), req)
		require.Error(t, err)
		assert.ErrorIs(t, err, xkms.ErrInvalidEncodingPEM)
	})

	t.Run("fails saveCert with invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.saveCert",
			Params:  json.RawMessage(`invalid`),
			ID:      1,
		}

		_, err := server.handleSaveCert(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})

	t.Run("gets certificate", func(t *testing.T) {
		params := GetCertParams{KeyID: "test-cert-key"}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.getCert",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleGetCert(context.Background(), req)
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
			Method:  "xkms.getCert",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleGetCert(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key_id is required")
	})

	t.Run("getCert fails with invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.getCert",
			Params:  json.RawMessage(`invalid`),
			ID:      1,
		}

		_, err := server.handleGetCert(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})

	t.Run("checks certificate exists", func(t *testing.T) {
		params := CertExistsParams{KeyID: "test-cert-key"}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.certExists",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleCertExists(context.Background(), req)
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
			Method:  "xkms.certExists",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleCertExists(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key_id is required")
	})

	t.Run("certExists fails with invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.certExists",
			Params:  json.RawMessage(`invalid`),
			ID:      1,
		}

		_, err := server.handleCertExists(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})

	t.Run("lists certificates", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.listCerts",
			ID:      1,
		}

		result, err := server.handleListCerts(context.Background(), req)
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
			Method:  "xkms.deleteCert",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleDeleteCert(context.Background(), req)
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
			Method:  "xkms.deleteCert",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleDeleteCert(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key_id is required")
	})

	t.Run("deleteCert fails with invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.deleteCert",
			Params:  json.RawMessage(`invalid`),
			ID:      1,
		}

		_, err := server.handleDeleteCert(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})
}

// TestHandler_CertificateChain tests the certificate chain handlers
func TestHandler_CertificateChain(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

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
			Method:  "xkms.saveCertChain",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleSaveCertChain(context.Background(), req)
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
			Method:  "xkms.saveCertChain",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleSaveCertChain(context.Background(), req)
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
			Method:  "xkms.saveCertChain",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleSaveCertChain(context.Background(), req)
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
			Method:  "xkms.saveCertChain",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleSaveCertChain(context.Background(), req)
		require.Error(t, err)
		assert.ErrorIs(t, err, xkms.ErrInvalidEncodingPEM)
	})

	t.Run("saveCertChain fails with invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.saveCertChain",
			Params:  json.RawMessage(`invalid`),
			ID:      1,
		}

		_, err := server.handleSaveCertChain(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})

	t.Run("gets certificate chain", func(t *testing.T) {
		params := GetCertChainParams{KeyID: "test-chain-key"}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.getCertChain",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleGetCertChain(context.Background(), req)
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
			Method:  "xkms.getCertChain",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleGetCertChain(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key_id is required")
	})

	t.Run("getCertChain fails with invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.getCertChain",
			Params:  json.RawMessage(`invalid`),
			ID:      1,
		}

		_, err := server.handleGetCertChain(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})
}

// TestHandler_AsymmetricEncrypt tests the asymmetric encrypt handler
func TestHandler_AsymmetricEncrypt(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	// Generate an RSA key for encryption
	genParams := GenerateKeyParams{
		KeyID:   "test-asym-encrypt-key",
		Backend: "software",
		KeyType: "rsa", Algorithm: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(context.Background(), genReq)
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
			Method:  "xkms.asymmetricEncrypt",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleAsymmetricEncrypt(context.Background(), req)
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
			Method:  "xkms.asymmetricEncrypt",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleAsymmetricEncrypt(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key_id is required")
	})

	t.Run("fails with invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.asymmetricEncrypt",
			Params:  json.RawMessage(`invalid`),
			ID:      1,
		}

		_, err := server.handleAsymmetricEncrypt(context.Background(), req)
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
			Method:  "xkms.asymmetricEncrypt",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleAsymmetricEncrypt(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid backend")
	})

	t.Run("fails with ECDSA key (not RSA)", func(t *testing.T) {
		// Generate an ECDSA key
		genParams := GenerateKeyParams{
			KeyID:   "test-ecdsa-for-encrypt",
			Backend: "software",
			KeyType: "ecdsa", Algorithm: "ecdsa",
			Curve: "P-256",
		}
		genParamsJSON, _ := json.Marshal(genParams)
		genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.generateKey", Params: genParamsJSON, ID: 1}
		_, err := server.handleGenerateKey(context.Background(), genReq)
		require.NoError(t, err)

		params := AsymmetricEncryptParams{
			KeyID:     "test-ecdsa-for-encrypt",
			Backend:   "software",
			Plaintext: []byte("data"),
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.asymmetricEncrypt",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err = server.handleAsymmetricEncrypt(context.Background(), req)
		require.Error(t, err)
		// The key-type refusal now comes from the service layer, which owns
		// the OAEP construction; the wording is its own.
		assert.Contains(t, err.Error(), "key is not RSA")
	})
}

// TestHandler_WrapKey tests the wrap key handler
func TestHandler_WrapKey(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	t.Run("fails with invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.wrapKey",
			Params:  json.RawMessage(`invalid`),
			ID:      1,
		}

		_, err := server.handleWrapKey(context.Background(), req)
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
			Method:  "xkms.wrapKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleWrapKey(context.Background(), req)
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
			Method:  "xkms.wrapKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleWrapKey(context.Background(), req)
		require.Error(t, err)
		// WrapKey now routes through the service layer, which parses the DER
		// itself and reports "...wrapping public key", not the MCP-local
		// wrapper's former "failed to parse public key".
		assert.Contains(t, err.Error(), "failed to parse wrapping public key")
	})
}

// TestHandler_SymmetricEncrypt tests the symmetric encrypt handler
func TestHandler_SymmetricEncrypt(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	// Generate a symmetric key using the software backend
	genParams := GenerateKeyParams{
		KeyID:     "test-sym-key",
		Backend:   "software",
		KeyType:   "symmetric",
		Algorithm: "aes256-gcm",
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(context.Background(), genReq)
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
			Method:  "xkms.encrypt",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleEncrypt(context.Background(), req)
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
			Method:  "xkms.encrypt",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleEncrypt(context.Background(), req)
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
			Method:  "xkms.encrypt",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleEncrypt(context.Background(), req)
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
			Method:  "xkms.encrypt",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleEncrypt(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "plaintext is required")
	})

	t.Run("fails with invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.encrypt",
			Params:  json.RawMessage(`invalid`),
			ID:      1,
		}

		_, err := server.handleEncrypt(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})
}

// TestHandler_SymmetricDecrypt tests the symmetric decrypt handler
func TestHandler_SymmetricDecrypt(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	// Generate a symmetric key using the software backend
	genParams := GenerateKeyParams{
		KeyID:     "test-sym-decrypt-key",
		Backend:   "software",
		KeyType:   "symmetric",
		Algorithm: "aes256-gcm",
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(context.Background(), genReq)
	require.NoError(t, err)

	// Encrypt data first using the software backend
	encryptParams := EncryptParams{
		KeyID:     "test-sym-decrypt-key",
		Backend:   "software",
		Plaintext: []byte("secret data"),
	}
	encryptParamsJSON, _ := json.Marshal(encryptParams)
	encryptReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.encrypt", Params: encryptParamsJSON, ID: 1}
	encryptResult, err := server.handleEncrypt(context.Background(), encryptReq)
	require.NoError(t, err)

	encResult := encryptResult.(EncryptResult)

	t.Run("decrypts data", func(t *testing.T) {
		params := DecryptParams{
			KeyID:        "test-sym-decrypt-key",
			Backend:      "software",
			Ciphertext:   encResult.Ciphertext,
			Nonce:        encResult.Nonce,
			Tag:          encResult.Tag,
			GCMNonceMode: encResult.GCMNonceMode,
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.decrypt",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleDecrypt(context.Background(), req)
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
		encryptReqAAD := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.encrypt", Params: encryptParamsAADJSON, ID: 1}
		encryptResultAAD, err := server.handleEncrypt(context.Background(), encryptReqAAD)
		require.NoError(t, err)

		encResultAAD := encryptResultAAD.(EncryptResult)

		params := DecryptParams{
			KeyID:          "test-sym-decrypt-key",
			Backend:        "software",
			Ciphertext:     encResultAAD.Ciphertext,
			Nonce:          encResultAAD.Nonce,
			Tag:            encResultAAD.Tag,
			AdditionalData: []byte("aad"),
			GCMNonceMode:   encResultAAD.GCMNonceMode,
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.decrypt",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleDecrypt(context.Background(), req)
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
			Method:  "xkms.decrypt",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleDecrypt(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key_id is required")
	})

	t.Run("fails with invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.decrypt",
			Params:  json.RawMessage(`invalid`),
			ID:      1,
		}

		_, err := server.handleDecrypt(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})

	t.Run("decrypts without specifying backend", func(t *testing.T) {
		params := DecryptParams{
			KeyID:        "test-sym-decrypt-key",
			Ciphertext:   encResult.Ciphertext,
			Nonce:        encResult.Nonce,
			Tag:          encResult.Tag,
			GCMNonceMode: encResult.GCMNonceMode,
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.decrypt",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleDecrypt(context.Background(), req)
		require.NoError(t, err)

		decResult, ok := result.(DecryptResult)
		require.True(t, ok)
		assert.Equal(t, []byte("secret data"), decResult.Plaintext)
	})
}

// TestHandler_CertExists_NotFound tests checking for non-existent cert
func TestHandler_CertExists_NotFound(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	t.Run("returns false for non-existent cert", func(t *testing.T) {
		params := CertExistsParams{KeyID: "non-existent-cert"}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.certExists",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleCertExists(context.Background(), req)
		require.NoError(t, err)

		existsResult, ok := result.(CertExistsResult)
		require.True(t, ok)
		assert.False(t, existsResult.Exists)
	})
}

// TestHandler_GetCert_NotFound tests getting a non-existent cert
func TestHandler_GetCert_NotFound(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	t.Run("fails for non-existent cert", func(t *testing.T) {
		params := GetCertParams{KeyID: "non-existent-cert"}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.getCert",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleGetCert(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get certificate")
	})
}

// TestHandler_GetCertChain_NotFound tests getting a non-existent cert chain
func TestHandler_GetCertChain_NotFound(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	t.Run("fails for non-existent cert chain", func(t *testing.T) {
		params := GetCertChainParams{KeyID: "non-existent-chain"}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.getCertChain",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleGetCertChain(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get certificate chain")
	})
}

// TestHandler_DeleteCert_NotFound tests deleting a non-existent cert
func TestHandler_DeleteCert_NotFound(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	t.Run("fails for non-existent cert", func(t *testing.T) {
		params := DeleteCertParams{KeyID: "non-existent-cert"}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.deleteCert",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleDeleteCert(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to delete certificate")
	})
}

// TestHandler_Encrypt_NonExistentKey tests encrypting with non-existent key
func TestHandler_Encrypt_NonExistentKey(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	t.Run("fails with non-existent key", func(t *testing.T) {
		params := EncryptParams{
			KeyID:     "non-existent-encrypt-key",
			Backend:   "software",
			Plaintext: []byte("secret data"),
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.encrypt",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleEncrypt(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key not found")
	})
}

// TestHandler_Verify_InvalidSignature tests verify with invalid signature
func TestHandler_Verify_InvalidSignature(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	// Generate a key
	genParams := GenerateKeyParams{
		KeyID:   "test-verify-invalid-key",
		Backend: "software",
		KeyType: "rsa", Algorithm: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(context.Background(), genReq)
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
			Method:  "xkms.verify",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleVerify(context.Background(), req)
		require.NoError(t, err)

		verifyResult, ok := result.(VerifyResult)
		require.True(t, ok)
		assert.False(t, verifyResult.Valid)
	})
}

// TestHandler_Verify_SignatureAsArray tests verify with signature as JSON array of numbers
func TestHandler_Verify_SignatureAsArray(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	// Generate an RSA key
	genParams := GenerateKeyParams{
		KeyID:   "test-verify-array-key",
		Backend: "software",
		KeyType: "rsa", Algorithm: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(context.Background(), genReq)
	require.NoError(t, err)

	// Sign data
	signParams := SignParams{
		KeyID:   "test-verify-array-key",
		Backend: "software",
		Data:    []byte("test data"),
		Hash:    "SHA256",
	}
	signParamsJSON, _ := json.Marshal(signParams)
	signReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.sign", Params: signParamsJSON, ID: 1}
	signResult, err := server.handleSign(context.Background(), signReq)
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
			Method:  "xkms.verify",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleVerify(context.Background(), req)
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
			Method:  "xkms.verify",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleVerify(context.Background(), req)
		require.NoError(t, err)

		verifyResult, ok := result.(VerifyResult)
		require.True(t, ok)
		assert.False(t, verifyResult.Valid) // Should fail but not error
	})
}

// TestHandler_GetTLSCertificate_Success tests getting TLS certificate successfully
func TestHandler_GetTLSCertificate_Success(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	// Generate a key first
	genParams := GenerateKeyParams{
		KeyID:   "test-tls-cert-key",
		Backend: "software",
		KeyType: "rsa", Algorithm: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(context.Background(), genReq)
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
	saveCertReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.saveCert", Params: saveCertParamsJSON, ID: 1}
	_, err = server.handleSaveCert(context.Background(), saveCertReq)
	require.NoError(t, err)

	t.Run("gets TLS certificate", func(t *testing.T) {
		params := GetTLSCertificateParams{
			KeyID:   "test-tls-cert-key",
			Backend: "software",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.getTLSCertificate",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleGetTLSCertificate(context.Background(), req)
		require.NoError(t, err)

		tlsResult, ok := result.(transport.GetTLSCertificateResponse)
		require.True(t, ok)
		assert.Contains(t, tlsResult.CertificatePEM, "BEGIN CERTIFICATE")
	})

	t.Run("gets TLS certificate without specifying backend", func(t *testing.T) {
		params := GetTLSCertificateParams{
			KeyID: "test-tls-cert-key",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.getTLSCertificate",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleGetTLSCertificate(context.Background(), req)
		require.NoError(t, err)

		tlsResult, ok := result.(transport.GetTLSCertificateResponse)
		require.True(t, ok)
		assert.Contains(t, tlsResult.CertificatePEM, "BEGIN CERTIFICATE")
	})
}

// TestHandler_SymmetricEncrypt_WithNonSymmetricBackend tests encrypt error handling
func TestHandler_SymmetricEncrypt_WithNonSymmetricBackend(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	// Generate an RSA key (not symmetric)
	genParams := GenerateKeyParams{
		KeyID:   "test-rsa-not-sym",
		Backend: "software",
		KeyType: "rsa", Algorithm: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(context.Background(), genReq)
	require.NoError(t, err)

	// Encrypting an RSA key through xkms.encrypt is no longer an error. The
	// service layer falls back to PKCS#1 v1.5 encryption under the key's public
	// half, which is what makes a key wrapped under an RSA KEK work; this
	// transport now gets that behaviour instead of its own refusal, matching
	// REST and gRPC.
	t.Run("refuses the PKCS#1 v1.5 fallback unless legacy wrap is enabled", func(t *testing.T) {
		previous := types.AllowLegacyKeyWrap()
		types.SetAllowLegacyKeyWrap(false)
		t.Cleanup(func() { types.SetAllowLegacyKeyWrap(previous) })

		paramsJSON, _ := json.Marshal(EncryptParams{
			KeyID:     "test-rsa-not-sym",
			Backend:   "software",
			Plaintext: []byte("secret data"),
		})
		_, err := server.handleEncrypt(context.Background(), &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.encrypt",
			Params:  paramsJSON,
			ID:      1,
		})
		require.Error(t, err)
	})

	t.Run("falls back to asymmetric encryption for an RSA key", func(t *testing.T) {
		// PKCS#1 v1.5 encryption is legacy and refused by default
		// (go-xkms#1205); this case opts in to exercise the fallback.
		previous := types.AllowLegacyKeyWrap()
		types.SetAllowLegacyKeyWrap(true)
		t.Cleanup(func() { types.SetAllowLegacyKeyWrap(previous) })

		params := EncryptParams{
			KeyID:     "test-rsa-not-sym",
			Backend:   "software",
			Plaintext: []byte("secret data"),
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.encrypt",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleEncrypt(context.Background(), req)
		if err != nil {
			// This RPC's asymmetric fallback deliberately mirrors
			// PKCS#11's CKM_RSA_PKCS mechanism -- raw PKCS#1 v1.5
			// encryption, no OAEP digest involved -- for the
			// local-fallback KEK-wrap path (see
			// pkg/xkms/servicer_crypto.go's Encrypt). crypto/rsa refuses
			// that construction outright under GODEBUG=fips140=only.
			if fips140.Enforced() {
				return
			}
			require.NoError(t, err)
		}

		encryptResult, ok := result.(EncryptResult)
		require.True(t, ok)
		require.NotEmpty(t, encryptResult.Ciphertext)
		assert.NotEqual(t, []byte("secret data"), encryptResult.Ciphertext)

		// The ciphertext must be openable by the key that produced it, and by
		// the matching padding scheme.
		decParams := DecryptParams{
			KeyID:      "test-rsa-not-sym",
			Backend:    "software",
			Ciphertext: encryptResult.Ciphertext,
		}
		decParamsJSON, _ := json.Marshal(decParams)
		decReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.decrypt", Params: decParamsJSON, ID: 2}
		decResult, err := server.handleDecrypt(context.Background(), decReq)
		require.NoError(t, err)
		assert.Equal(t, []byte("secret data"), decResult.(DecryptResult).Plaintext)
	})
}

// TestHandler_SHA1Hash asserts that the MCP transport applies the same
// weak-hash policy as every other transport. It used to resolve hash names from
// its own private table, which admitted SHA-1 unconditionally, so a caller
// could obtain a SHA-1 signature over MCP that REST and gRPC refuse.
//
// The second half asserts the escape hatch still reaches this transport: an
// operator who accepted the compliance gap must actually be able to do the
// legacy interop it was granted for.
func TestHandler_SHA1Hash(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	// Generate an RSA key
	genParams := GenerateKeyParams{
		KeyID:   "test-verify-sha1-key",
		Backend: "software",
		KeyType: "rsa", Algorithm: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(context.Background(), genReq)
	require.NoError(t, err)

	signParams := SignParams{
		KeyID:   "test-verify-sha1-key",
		Backend: "software",
		Data:    []byte("test data sha1"),
		Hash:    "SHA1",
	}
	signParamsJSON, _ := json.Marshal(signParams)
	signReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.sign", Params: signParamsJSON, ID: 1}

	t.Run("SHA-1 signing is refused and yields no signature", func(t *testing.T) {
		result, signErr := server.handleSign(context.Background(), signReq)
		require.Error(t, signErr)
		require.ErrorIs(t, signErr, xkms.ErrInvalidHashFunction)
		assert.Nil(t, result)
	})

	t.Run("SHA-1 verification is refused", func(t *testing.T) {
		params := VerifyParams{
			KeyID:     "test-verify-sha1-key",
			Backend:   "software",
			Data:      []byte("test data sha1"),
			Signature: []byte("irrelevant"),
			Hash:      "SHA1",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.verify", Params: paramsJSON, ID: 1}
		result, verifyErr := server.handleVerify(context.Background(), req)
		require.Error(t, verifyErr)
		require.ErrorIs(t, verifyErr, xkms.ErrInvalidHashFunction)
		assert.Nil(t, result)
	})

	t.Run("SHA-1 round-trips under the weak-hash policy", func(t *testing.T) {
		types.SetAllowWeakHashes(true)
		defer types.SetAllowWeakHashes(false)

		// SetAllowWeakHashes(true) is a deliberate no-op under FIPSMode():
		// the Go Cryptographic Module's approved-algorithm boundary is the
		// ceiling this repository's own policy switch must never be able
		// to re-open (see pkg/types/hashpolicy.go), so SHA-1 signing stays
		// refused under GODEBUG=fips140=only regardless of the policy.
		if types.FIPSMode() {
			_, signErr := server.handleSign(context.Background(), signReq)
			require.ErrorIs(t, signErr, xkms.ErrInvalidHashFunction)
			return
		}

		signResult, signErr := server.handleSign(context.Background(), signReq)
		require.NoError(t, signErr)
		signature := signResult.(SignResult).Signature
		require.NotEmpty(t, signature)

		params := VerifyParams{
			KeyID:     "test-verify-sha1-key",
			Backend:   "software",
			Data:      []byte("test data sha1"),
			Signature: signature,
			Hash:      "SHA1",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.verify", Params: paramsJSON, ID: 1}
		result, verifyErr := server.handleVerify(context.Background(), req)
		require.NoError(t, verifyErr)

		verifyResult, ok := result.(VerifyResult)
		require.True(t, ok)
		assert.True(t, verifyResult.Valid)
	})
}

// TestHandler_Encrypt_DefaultBackend tests encrypt with default backend
func TestHandler_Encrypt_DefaultBackend(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	// Generate a symmetric key using default backend name
	genParams := GenerateKeyParams{
		KeyID:     "test-encrypt-default-backend",
		Backend:   "software",
		KeyType:   "symmetric",
		Algorithm: "aes256-gcm",
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(context.Background(), genReq)
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
			Method:  "xkms.encrypt",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleEncrypt(context.Background(), req)
		require.NoError(t, err)

		encResult, ok := result.(EncryptResult)
		require.True(t, ok)
		assert.NotEmpty(t, encResult.Ciphertext)
	})
}

// TestHandler_GetImportParameters_Success tests successful import parameters retrieval
func TestHandler_GetImportParameters_Success(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	t.Run("gets import parameters successfully", func(t *testing.T) {
		params := GetImportParametersParams{
			KeyID:     "test-import-key",
			Backend:   "software",
			Algorithm: "RSAES_OAEP_SHA_256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.getImportParameters",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleGetImportParameters(context.Background(), req)
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
	defer cleanupXKMS()

	// First get import parameters to get a valid wrapping key
	importParamsReq := GetImportParametersParams{
		KeyID:     "test-wrap-key",
		Backend:   "software",
		Algorithm: "RSAES_OAEP_SHA_256",
	}
	importParamsJSON, _ := json.Marshal(importParamsReq)
	importReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.getImportParameters", Params: importParamsJSON, ID: 1}
	importResult, err := server.handleGetImportParameters(context.Background(), importReq)
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
			Method:  "xkms.wrapKey",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleWrapKey(context.Background(), req)
		require.NoError(t, err)

		wrapResult, ok := result.(WrapKeyResult)
		require.True(t, ok)
		assert.NotEmpty(t, wrapResult.WrappedKey)
	})
}

// TestHandler_ImportExportKeyFlow tests export key flow error handling
func TestHandler_ImportExportKeyFlow(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	// Generate an exportable key
	genParams := GenerateKeyParams{
		KeyID:   "test-export-flow-key",
		Backend: "software",
		KeyType: "rsa", Algorithm: "rsa",
		KeySize:    2048,
		Exportable: true,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(context.Background(), genReq)
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
			Method:  "xkms.exportKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleExportKey(context.Background(), req)
		// This will error due to key size limitations
		require.Error(t, err)
	})
}

// copyKeyThroughHandler generates a software key with the given
// exportability through the MCP generate handler and then asks the copy
// handler to copy it, returning the copy's error.
func copyKeyThroughHandler(t *testing.T, server *Server, keyID string, exportable bool) error {
	t.Helper()
	// A 32-byte AES key fits in one RSA-OAEP block, so the export's wrap
	// step cannot fail for a reason unrelated to exportability. (An RSA
	// private key needs the hybrid RSA+AES algorithm; under it the export
	// passes the same way and fails at the same import step as below.)
	genParams := GenerateKeyParams{
		KeyID:      keyID,
		Backend:    "software",
		KeyType:    "symmetric",
		Algorithm:  "aes256-gcm",
		Exportable: exportable,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(context.Background(), genReq)
	require.NoError(t, err)

	params := CopyKeyParams{
		SourceBackend: "software",
		SourceKeyID:   keyID,
		DestBackend:   "software",
		DestKeyID:     keyID + "-copy",
		Algorithm:     string(backend.WrappingAlgorithmRSAES_OAEP_SHA_256),
	}
	paramsJSON, _ := json.Marshal(params)
	req := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.copyKey", Params: paramsJSON, ID: 1}
	_, err = server.handleCopyKey(context.Background(), req)
	return err
}

// TestHandler_CopyKey_RefusesANonExportableKey: the source key's STORED
// exportability decides, and a key generated non-exportable is refused at
// the export step with the backend's typed error.
func TestHandler_CopyKey_RefusesANonExportableKey(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	err := copyKeyThroughHandler(t, server, "test-copy-nonexportable", false)
	require.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrKeyNotExportable,
		"a non-exportable key must be refused at the export step, got %v", err)
}

// TestHandler_CopyKey_ExportsAnExportableKey is the half that was vacuous
// before #155: the handler built the source attributes by hand with
// Exportable left false, so EVERY copy was refused at the export step and
// the refusal test above passed whether or not the key was exportable. The
// handler now delegates to the service, which resolves the stored
// attributes, so an exportable key gets past the export step.
//
// The copy is not asserted to complete: the software backend's ExportKey
// wraps under a wrapping key it mints itself while the service replaces the
// import token with the destination's, so the import step fails on the
// unwrap. That is #154's remaining half, a contract question for the owner,
// and it is pinned here by type so that fixing it changes exactly one line.
func TestHandler_CopyKey_ExportsAnExportableKey(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	err := copyKeyThroughHandler(t, server, "test-copy-exportable", true)
	assert.NotErrorIs(t, err, backend.ErrKeyNotExportable,
		"an exportable key must not be refused at the export step")
	if err != nil {
		var opErr *xkms.ErrKeyOperation
		require.ErrorAs(t, err, &opErr, "a residual failure must be a typed key-operation error, got %v", err)
		assert.Equal(t, "import key", opErr.Operation,
			"the only step allowed to fail for an exportable key is the import (#154); got %v", err)
	}
}

// CopyKeyParams deliberately carries no exportability field: a request
// must not be able to assert that a key may leave the backend.
func TestCopyKeyParams_CannotAssertExportability(t *testing.T) {
	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(`{"source_backend":"software","source_key_id":"k","dest_backend":"software","dest_key_id":"c","algorithm":"RSAES_OAEP_SHA_256","exportable":true}`), &raw))
	var params CopyKeyParams
	require.NoError(t, json.Unmarshal([]byte(`{"exportable":true}`), &params))
	// Reflect over the struct rather than trusting the decode: an added field
	// would decode "exportable" and this test must notice.
	typ := reflect.TypeOf(params)
	for i := 0; i < typ.NumField(); i++ {
		assert.NotContains(t, typ.Field(i).Tag.Get("json"), "exportable",
			"CopyKeyParams must not carry an exportability field")
	}
}

// TestHandler_ExportKey_NonExportableKey tests export error for non-exportable key
func TestHandler_ExportKey_NonExportableKey(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	// Generate a non-exportable key
	genParams := GenerateKeyParams{
		KeyID:   "test-export-nonexp",
		Backend: "software",
		KeyType: "rsa", Algorithm: "rsa",
		KeySize:    2048,
		Exportable: false,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(context.Background(), genReq)
	require.NoError(t, err)

	t.Run("fails to export non-exportable key", func(t *testing.T) {
		params := ExportKeyParams{
			KeyID:     "test-export-nonexp",
			Algorithm: "RSAES_OAEP_SHA_256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.exportKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleExportKey(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not exportable")
	})
}

// TestHandler_Decrypt_WithEmptyCiphertext tests decrypt with empty ciphertext
func TestHandler_Decrypt_WithEmptyCiphertext(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	t.Run("fails with empty ciphertext", func(t *testing.T) {
		params := DecryptParams{
			KeyID:      "any-key",
			Backend:    "software",
			Ciphertext: []byte{},
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.decrypt",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleDecrypt(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key not found")
	})
}

// TestHandler_DeleteKey_ErrorPaths tests various error paths in deleteKey
func TestHandler_DeleteKey_ErrorPaths(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	t.Run("invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.deleteKey",
			Params:  json.RawMessage(`{invalid`),
			ID:      1,
		}

		_, err := server.handleDeleteKey(context.Background(), req)
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
			Method:  "xkms.deleteKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleDeleteKey(context.Background(), req)
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
			Method:  "xkms.deleteKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleDeleteKey(context.Background(), req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "key not found")
	})
}

// TestHandler_Verify_ErrorPaths tests error paths in handleVerify
func TestHandler_Verify_ErrorPaths(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	t.Run("invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.verify",
			Params:  json.RawMessage(`{invalid`),
			ID:      1,
		}

		_, err := server.handleVerify(context.Background(), req)
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
			Method:  "xkms.verify",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleVerify(context.Background(), req)
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
			Method:  "xkms.verify",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleVerify(context.Background(), req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "key not found")
	})
}

// TestHandler_CopyKey_ErrorPaths tests error paths in handleCopyKey
func TestHandler_CopyKey_ErrorPaths(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

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
			Method:  "xkms.copyKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleCopyKey(context.Background(), req)
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
			Method:  "xkms.copyKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleCopyKey(context.Background(), req)
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
			Method:  "xkms.copyKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleCopyKey(context.Background(), req)
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
			Method:  "xkms.copyKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleCopyKey(context.Background(), req)
		assert.Error(t, err)
		assertCopyKeyBackendError(t, err, "source")
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
			Method:  "xkms.copyKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleCopyKey(context.Background(), req)
		assert.Error(t, err)
		assertCopyKeyBackendError(t, err, "destination")
	})
}

// TestHandler_Decrypt_KeyNotFoundAnywhere tests decrypt when key is not found in any backend
func TestHandler_Decrypt_KeyNotFoundAnywhere(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	t.Run("returns error when key not found in any backend", func(t *testing.T) {
		params := DecryptParams{
			KeyID: "non-existent-decrypt-key",
			// No backend - will search both and fail
			Ciphertext: []byte("dummy"),
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.decrypt",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleDecrypt(context.Background(), req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "key not found")
	})
}

// TestHandler_Verify_SignatureAsStruct tests verify with signature as a struct/map type
// This covers the default case in signature conversion (lines 459-463)
func TestHandler_Verify_SignatureAsStruct(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	// Generate an RSA key
	genParams := GenerateKeyParams{
		KeyID:   "test-verify-struct-key",
		Backend: "software",
		KeyType: "rsa", Algorithm: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(context.Background(), genReq)
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
			Method:  "xkms.verify",
			Params:  paramsJSON,
			ID:      1,
		}

		// A JSON object is not one of the three signature encodings this
		// transport accepts. It used to be marshaled back to JSON and
		// unmarshaled into a byte slice, an operation that fails, whose error
		// was discarded; the empty slice that survived was then reported as an
		// invalid signature -- an answer indistinguishable from a genuine
		// verification failure.
		_, err := server.handleVerify(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "signature")
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
			Method:  "xkms.verify",
			Params:  paramsJSON,
			ID:      1,
		}

		// A bare number is not a signature encoding either; see the map case
		// above for why decoding it to an empty slice was worse than refusing.
		_, err := server.handleVerify(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "signature")
	})
}

// TestHandler_Verify_WithByteSliceSignature tests verify with signature passed as []byte directly
func TestHandler_Verify_WithByteSliceSignature(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	// Generate an RSA key
	genParams := GenerateKeyParams{
		KeyID:   "test-verify-bytes-key",
		Backend: "software",
		KeyType: "rsa", Algorithm: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(context.Background(), genReq)
	require.NoError(t, err)

	// Sign data
	signParams := SignParams{
		KeyID:   "test-verify-bytes-key",
		Backend: "software",
		Data:    []byte("test data"),
		Hash:    "SHA256",
	}
	signParamsJSON, _ := json.Marshal(signParams)
	signReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.sign", Params: signParamsJSON, ID: 1}
	signResult, err := server.handleSign(context.Background(), signReq)
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
			Method:  "xkms.verify",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleVerify(context.Background(), req)
		require.NoError(t, err)

		verifyResult, ok := result.(VerifyResult)
		require.True(t, ok)
		assert.True(t, verifyResult.Valid)
	})
}

// TestHandler_ListCerts_Success tests successful certificate listing
func TestHandler_ListCerts_Success(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

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
	saveCertReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.saveCert", Params: saveCertParamsJSON, ID: 1}
	_, err = server.handleSaveCert(context.Background(), saveCertReq)
	require.NoError(t, err)

	t.Run("lists certificates with at least one cert", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.listCerts",
			ID:      1,
		}

		result, err := server.handleListCerts(context.Background(), req)
		require.NoError(t, err)

		listResult, ok := result.(ListCertsResult)
		require.True(t, ok)
		assert.Contains(t, listResult.KeyIDs, "list-test-cert")
		assert.GreaterOrEqual(t, len(listResult.KeyIDs), 1)
	})
}

// assertCopyKeyBackendError asserts that a copy_key failure was the service
// refusing to resolve the named backend (source or destination), by type
// rather than by message text: the handler delegates to
// XKMSService.CopyKey, whose backend errors are *xkms.ErrCopyKeyBackend.
func assertCopyKeyBackendError(t *testing.T, err error, role string) {
	t.Helper()
	require.Error(t, err)
	var backendErr *xkms.ErrCopyKeyBackend
	require.ErrorAs(t, err, &backendErr, "expected a copy-key backend error, got %v", err)
	assert.Equal(t, role, backendErr.Role)
}
