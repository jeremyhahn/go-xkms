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
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHandler_Seal tests the seal handler for sealing data with a backend.
// Note: The current handler implementation only sets CN in KeyAttributes,
// which is insufficient for the software backend that requires StoreType.
// These tests document the current behavior.
func TestHandler_Seal(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("fails with invalid params - malformed JSON", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.seal",
			Params:  json.RawMessage(`invalid json`),
			ID:      1,
		}

		_, err := server.handleSeal(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})

	t.Run("fails with missing data field", func(t *testing.T) {
		params := SealParams{
			Backend: "software",
			KeyID:   "test-key",
			// Data is empty/missing
		}
		paramsJSON, err := json.Marshal(params)
		require.NoError(t, err)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.seal",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err = server.handleSeal(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "data is required")
	})

	t.Run("fails with empty data array", func(t *testing.T) {
		params := SealParams{
			Backend: "software",
			KeyID:   "test-key",
			Data:    []byte{}, // Empty array
		}
		paramsJSON, err := json.Marshal(params)
		require.NoError(t, err)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.seal",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err = server.handleSeal(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "data is required")
	})

	t.Run("fails with invalid backend name", func(t *testing.T) {
		params := SealParams{
			Backend: "nonexistent-backend",
			KeyID:   "test-key",
			Data:    []byte("some data"),
		}
		paramsJSON, err := json.Marshal(params)
		require.NoError(t, err)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.seal",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err = server.handleSeal(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to seal data")
	})

	t.Run("fails when backend name is empty", func(t *testing.T) {
		params := SealParams{
			Backend: "", // Empty backend name
			KeyID:   "test-key",
			Data:    []byte("some data"),
		}
		paramsJSON, err := json.Marshal(params)
		require.NoError(t, err)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.seal",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err = server.handleSeal(context.Background(), req)
		require.Error(t, err)
		// The service validates backend name cannot be empty
		assert.Contains(t, err.Error(), "failed to seal data")
	})

	// Note: The following test documents that the software backend requires
	// complete KeyAttributes (including StoreType), which the current handler
	// does not provide when only KeyID is given.
	t.Run("fails when KeyAttributes lacks StoreType for software backend", func(t *testing.T) {
		// Generate a key first
		genParams := GenerateKeyParams{
			KeyID:   "seal-key-1",
			Backend: "software",
			KeyType: "rsa",
			KeySize: 2048,
		}
		genParamsJSON, err := json.Marshal(genParams)
		require.NoError(t, err)

		genReq := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.generateKey",
			Params:  genParamsJSON,
			ID:      1,
		}
		_, err = server.handleGenerateKey(genReq)
		require.NoError(t, err)

		// Try to seal - will fail because handler doesn't resolve full KeyAttributes
		params := SealParams{
			Backend: "software",
			KeyID:   "seal-key-1",
			Data:    []byte("secret data"),
		}
		paramsJSON, err := json.Marshal(params)
		require.NoError(t, err)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.seal",
			Params:  paramsJSON,
			ID:      1,
		}

		// The handler only sets CN, not StoreType, so the backend rejects it
		_, err = server.handleSeal(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to seal data")
	})

	t.Run("accepts valid seal params structure", func(t *testing.T) {
		// This test verifies the JSON parsing works correctly
		params := SealParams{
			Backend: "software",
			KeyID:   "some-key",
			Data:    []byte("test data"),
			AAD:     []byte("additional data"),
		}
		paramsJSON, err := json.Marshal(params)
		require.NoError(t, err)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.seal",
			Params:  paramsJSON,
			ID:      1,
		}

		// Call will fail at backend level but params parsing should succeed
		_, err = server.handleSeal(context.Background(), req)
		// Error should be from seal operation, not param parsing
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "invalid params")
	})
}

// TestHandler_Unseal tests the unseal handler for unsealing data with a backend.
// Note: The current handler implementation only sets CN in KeyAttributes,
// which is insufficient for the software backend that requires StoreType.
// These tests document the current behavior.
func TestHandler_Unseal(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("fails with invalid params - malformed JSON", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.unseal",
			Params:  json.RawMessage(`invalid json`),
			ID:      1,
		}

		_, err := server.handleUnseal(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})

	t.Run("fails with missing ciphertext field", func(t *testing.T) {
		params := UnsealParams{
			Backend: "software",
			KeyID:   "test-key",
			// Ciphertext is missing
			Nonce: []byte("some nonce"),
		}
		paramsJSON, err := json.Marshal(params)
		require.NoError(t, err)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.unseal",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err = server.handleUnseal(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ciphertext is required")
	})

	t.Run("fails with empty ciphertext array", func(t *testing.T) {
		params := UnsealParams{
			Backend:    "software",
			KeyID:      "test-key",
			Ciphertext: []byte{}, // Empty array
			Nonce:      []byte("some nonce"),
		}
		paramsJSON, err := json.Marshal(params)
		require.NoError(t, err)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.unseal",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err = server.handleUnseal(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ciphertext is required")
	})

	t.Run("fails with invalid backend name", func(t *testing.T) {
		params := UnsealParams{
			Backend:    "nonexistent-backend",
			KeyID:      "test-key",
			Ciphertext: []byte("some encrypted data"),
			Nonce:      []byte("nonce"),
		}
		paramsJSON, err := json.Marshal(params)
		require.NoError(t, err)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.unseal",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err = server.handleUnseal(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to unseal data")
	})

	t.Run("fails when backend name is empty", func(t *testing.T) {
		params := UnsealParams{
			Backend:    "", // Empty backend
			KeyID:      "test-key",
			Ciphertext: []byte("some encrypted data"),
			Nonce:      []byte("nonce"),
		}
		paramsJSON, err := json.Marshal(params)
		require.NoError(t, err)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.unseal",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err = server.handleUnseal(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to unseal data")
	})

	t.Run("accepts valid unseal params structure", func(t *testing.T) {
		// This test verifies the JSON parsing works correctly
		params := UnsealParams{
			Backend:    "software",
			KeyID:      "some-key",
			Ciphertext: []byte("encrypted data"),
			Nonce:      []byte("nonce"),
			Tag:        []byte("tag"),
			AAD:        []byte("additional data"),
		}
		paramsJSON, err := json.Marshal(params)
		require.NoError(t, err)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.unseal",
			Params:  paramsJSON,
			ID:      1,
		}

		// Call will fail at backend level but params parsing should succeed
		_, err = server.handleUnseal(context.Background(), req)
		// Error should be from unseal operation, not param parsing
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "invalid params")
	})

	t.Run("fails with corrupted encrypted data", func(t *testing.T) {
		params := UnsealParams{
			Backend:    "software",
			KeyID:      "test-key",
			Ciphertext: []byte{0xFF, 0xFE, 0xFD}, // Invalid ciphertext
			Nonce:      []byte("invalid-nonce"),
			Tag:        []byte("invalid-tag"),
		}
		paramsJSON, err := json.Marshal(params)
		require.NoError(t, err)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.unseal",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err = server.handleUnseal(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to unseal data")
	})
}

// TestHandler_CanSeal tests the canSeal handler for checking sealing capability
func TestHandler_CanSeal(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("returns true for software backend", func(t *testing.T) {
		params := CanSealParams{
			Backend: "software",
		}
		paramsJSON, err := json.Marshal(params)
		require.NoError(t, err)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.canSeal",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleCanSeal(req)
		require.NoError(t, err)

		canSealResult, ok := result.(CanSealResult)
		require.True(t, ok, "expected CanSealResult type")
		assert.True(t, canSealResult.CanSeal, "software backend should support sealing")
	})

	t.Run("uses default backend when not specified", func(t *testing.T) {
		params := CanSealParams{
			// Backend is empty - should use default
		}
		paramsJSON, err := json.Marshal(params)
		require.NoError(t, err)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.canSeal",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleCanSeal(req)
		require.NoError(t, err)

		canSealResult, ok := result.(CanSealResult)
		require.True(t, ok, "expected CanSealResult type")
		// Default backend (software) should support sealing
		assert.True(t, canSealResult.CanSeal, "default backend should support sealing")
	})

	t.Run("handles empty params object", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.canSeal",
			Params:  json.RawMessage(`{}`),
			ID:      1,
		}

		result, err := server.handleCanSeal(req)
		require.NoError(t, err)

		canSealResult, ok := result.(CanSealResult)
		require.True(t, ok, "expected CanSealResult type")
		// With empty params, should use default backend
		assert.True(t, canSealResult.CanSeal)
	})

	t.Run("fails with invalid params - malformed JSON", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.canSeal",
			Params:  json.RawMessage(`invalid json`),
			ID:      1,
		}

		_, err := server.handleCanSeal(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})

	t.Run("returns false for nonexistent backend", func(t *testing.T) {
		params := CanSealParams{
			Backend: "nonexistent-backend",
		}
		paramsJSON, err := json.Marshal(params)
		require.NoError(t, err)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.canSeal",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleCanSeal(req)
		require.NoError(t, err)

		canSealResult, ok := result.(CanSealResult)
		require.True(t, ok, "expected CanSealResult type")
		// Invalid/nonexistent backend should return false (not error)
		assert.False(t, canSealResult.CanSeal, "nonexistent backend should not support sealing")
	})

	t.Run("returns true for symmetric backend alias", func(t *testing.T) {
		// The test setup registers "symmetric" as an alias to software backend
		params := CanSealParams{
			Backend: "symmetric",
		}
		paramsJSON, err := json.Marshal(params)
		require.NoError(t, err)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.canSeal",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleCanSeal(req)
		require.NoError(t, err)

		canSealResult, ok := result.(CanSealResult)
		require.True(t, ok, "expected CanSealResult type")
		// "symmetric" is registered in test setup as an alias
		assert.True(t, canSealResult.CanSeal, "symmetric backend should support sealing")
	})
}

// TestHandler_Seal_ParamsValidation tests comprehensive parameter validation for seal
func TestHandler_Seal_ParamsValidation(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("accepts params with only required data field", func(t *testing.T) {
		// Minimal valid params - only data is provided
		params := SealParams{
			Data: []byte("minimal params test"),
		}
		paramsJSON, err := json.Marshal(params)
		require.NoError(t, err)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.seal",
			Params:  paramsJSON,
			ID:      1,
		}

		// Will fail due to empty backend, but should pass param validation
		_, err = server.handleSeal(context.Background(), req)
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "invalid params")
	})

	t.Run("accepts params with all fields populated", func(t *testing.T) {
		params := SealParams{
			Backend: "software",
			KeyID:   "full-params-key",
			Data:    []byte("full params test data"),
			AAD:     []byte("additional authenticated data"),
		}
		paramsJSON, err := json.Marshal(params)
		require.NoError(t, err)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.seal",
			Params:  paramsJSON,
			ID:      1,
		}

		// Will fail at backend level, but param parsing should succeed
		_, err = server.handleSeal(context.Background(), req)
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "invalid params")
	})

	t.Run("handles null data field", func(t *testing.T) {
		// JSON with explicit null for data
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.seal",
			Params:  json.RawMessage(`{"backend":"software","data":null}`),
			ID:      1,
		}

		_, err := server.handleSeal(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "data is required")
	})

	t.Run("handles extra unknown fields gracefully", func(t *testing.T) {
		// JSON with extra fields that aren't in the params struct
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.seal",
			Params:  json.RawMessage(`{"backend":"software","data":"dGVzdA==","extra_field":"ignored"}`),
			ID:      1,
		}

		// Should not error on parsing, may fail on backend
		_, err := server.handleSeal(context.Background(), req)
		// Extra fields are ignored in Go's JSON unmarshaling
		assert.NotContains(t, err.Error(), "invalid params")
	})
}

// TestHandler_Unseal_ParamsValidation tests comprehensive parameter validation for unseal
func TestHandler_Unseal_ParamsValidation(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("accepts params with only required ciphertext field", func(t *testing.T) {
		// Minimal valid params - only ciphertext is required
		params := UnsealParams{
			Ciphertext: []byte("encrypted data"),
		}
		paramsJSON, err := json.Marshal(params)
		require.NoError(t, err)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.unseal",
			Params:  paramsJSON,
			ID:      1,
		}

		// Will fail due to empty backend, but should pass param validation
		_, err = server.handleUnseal(context.Background(), req)
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "invalid params")
	})

	t.Run("accepts params with all fields populated", func(t *testing.T) {
		params := UnsealParams{
			Backend:    "software",
			KeyID:      "full-params-key",
			Ciphertext: []byte("encrypted payload"),
			Nonce:      []byte("12bytesnonce"),
			Tag:        []byte("16bytesauthtag!!"),
			AAD:        []byte("additional authenticated data"),
		}
		paramsJSON, err := json.Marshal(params)
		require.NoError(t, err)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.unseal",
			Params:  paramsJSON,
			ID:      1,
		}

		// Will fail at backend level, but param parsing should succeed
		_, err = server.handleUnseal(context.Background(), req)
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "invalid params")
	})

	t.Run("handles null ciphertext field", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.unseal",
			Params:  json.RawMessage(`{"backend":"software","ciphertext":null}`),
			ID:      1,
		}

		_, err := server.handleUnseal(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ciphertext is required")
	})
}

// TestHandler_CanSeal_Idempotent tests that canSeal is idempotent
func TestHandler_CanSeal_Idempotent(t *testing.T) {
	server := createTestServer(t)
	defer cleanupKeychain()

	t.Run("returns consistent results on multiple calls", func(t *testing.T) {
		params := CanSealParams{
			Backend: "software",
		}
		paramsJSON, err := json.Marshal(params)
		require.NoError(t, err)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.canSeal",
			Params:  paramsJSON,
			ID:      1,
		}

		// Call multiple times
		var results []bool
		for i := 0; i < 5; i++ {
			result, err := server.handleCanSeal(req)
			require.NoError(t, err)

			canSealResult, ok := result.(CanSealResult)
			require.True(t, ok)
			results = append(results, canSealResult.CanSeal)
		}

		// All results should be the same
		for i := 1; i < len(results); i++ {
			assert.Equal(t, results[0], results[i],
				"canSeal should return consistent results")
		}
	})
}
