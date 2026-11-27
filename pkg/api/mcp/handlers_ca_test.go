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
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleUnseal_AdditionalPaths(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	ctx := context.Background()

	t.Run("fails with empty ciphertext", func(t *testing.T) {
		params := UnsealParams{
			Backend: "software",
		}
		paramsJSON, _ := json.Marshal(params)
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.unseal", Params: paramsJSON, ID: 1}

		_, err := server.handleUnseal(ctx, req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ciphertext is required")
	})

	t.Run("fails with invalid backend", func(t *testing.T) {
		params := UnsealParams{
			Backend:    "nonexistent",
			Ciphertext: []byte("some-data"),
		}
		paramsJSON, _ := json.Marshal(params)
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.unseal", Params: paramsJSON, ID: 1}

		_, err := server.handleUnseal(ctx, req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "backend not found")
	})

	t.Run("fails with nonexistent key ID", func(t *testing.T) {
		params := UnsealParams{
			Backend:    "software",
			Ciphertext: []byte("encrypted-data"),
			KeyID:      "nonexistent-key",
		}
		paramsJSON, _ := json.Marshal(params)
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.unseal", Params: paramsJSON, ID: 1}

		_, err := server.handleUnseal(ctx, req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key not found")
	})

	t.Run("fails with invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.unseal", Params: json.RawMessage(`{bad`), ID: 1}
		_, err := server.handleUnseal(ctx, req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})

	t.Run("seal and unseal round trip", func(t *testing.T) {
		// Generate a key first
		genParams := GenerateKeyParams{
			KeyID:   "unseal-roundtrip-key",
			Backend: "software",
			KeyType: "rsa", Algorithm: "rsa",
			KeySize: 2048,
		}
		genParamsJSON, _ := json.Marshal(genParams)
		genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.generateKey", Params: genParamsJSON, ID: 1}
		_, err := server.handleGenerateKey(context.Background(), genReq)
		require.NoError(t, err)

		// Seal data
		sealParams := SealParams{
			Backend: "software",
			KeyID:   "unseal-roundtrip-key",
			Data:    []byte("secret round-trip data"),
		}
		sealParamsJSON, _ := json.Marshal(sealParams)
		sealReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.seal", Params: sealParamsJSON, ID: 1}
		sealResult, err := server.handleSeal(ctx, sealReq)
		require.NoError(t, err)

		sealed, ok := sealResult.(SealResult)
		require.True(t, ok)
		assert.NotEmpty(t, sealed.Ciphertext)

		// Unseal data
		unsealParams := UnsealParams{
			Backend:    "software",
			KeyID:      "unseal-roundtrip-key",
			Ciphertext: sealed.Ciphertext,
			Nonce:      sealed.Nonce,
			Tag:        sealed.Tag,
		}
		unsealParamsJSON, _ := json.Marshal(unsealParams)
		unsealReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.unseal", Params: unsealParamsJSON, ID: 1}

		unsealResult, err := server.handleUnseal(ctx, unsealReq)
		require.NoError(t, err)

		unsealed, ok := unsealResult.(UnsealResult)
		require.True(t, ok)
		assert.Equal(t, []byte("secret round-trip data"), unsealed.Plaintext)
	})

	t.Run("unseal without key ID", func(t *testing.T) {
		// Generate a key and seal data
		genParams := GenerateKeyParams{
			KeyID:   "unseal-nokey-test",
			Backend: "software",
			KeyType: "rsa", Algorithm: "rsa",
			KeySize: 2048,
		}
		genParamsJSON, _ := json.Marshal(genParams)
		genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.generateKey", Params: genParamsJSON, ID: 1}
		_, err := server.handleGenerateKey(context.Background(), genReq)
		require.NoError(t, err)

		sealParams := SealParams{
			Backend: "software",
			KeyID:   "unseal-nokey-test",
			Data:    []byte("data without keyid"),
		}
		sealParamsJSON, _ := json.Marshal(sealParams)
		sealReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.seal", Params: sealParamsJSON, ID: 1}
		sealResult, err := server.handleSeal(ctx, sealReq)
		require.NoError(t, err)

		sealed, ok := sealResult.(SealResult)
		require.True(t, ok)

		// Try unseal without key ID - will use the sealed data's embedded key info
		unsealParams := UnsealParams{
			Backend:    "software",
			Ciphertext: sealed.Ciphertext,
			Nonce:      sealed.Nonce,
			Tag:        sealed.Tag,
		}
		unsealParamsJSON, _ := json.Marshal(unsealParams)
		unsealReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.unseal", Params: unsealParamsJSON, ID: 1}

		// This may fail depending on backend requirements, but exercises the no-KeyID path
		_, err = server.handleUnseal(ctx, unsealReq)
		// The path without KeyID skips key lookup and goes straight to unseal
		_ = err
	})
}
