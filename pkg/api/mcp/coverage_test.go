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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHandler_UnwrapKey tests the unwrap key handler
func TestHandler_UnwrapKey(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	t.Run("fails with invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.unwrapKey",
			Params:  json.RawMessage(`invalid json`),
			ID:      1,
		}

		_, err := server.handleUnwrapKey(context.Background(), req)
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
			Method:  "xkms.unwrapKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleUnwrapKey(context.Background(), req)
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
			Method:  "xkms.unwrapKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleUnwrapKey(context.Background(), req)
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
			Method:  "xkms.unwrapKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleUnwrapKey(context.Background(), req)
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
			Method:  "xkms.unwrapKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleUnwrapKey(context.Background(), req)
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
			Method:  "xkms.unwrapKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleUnwrapKey(context.Background(), req)
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
			Method:  "xkms.unwrapKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err = server.handleUnwrapKey(context.Background(), req)
		require.Error(t, err)
		// UnwrapKey now routes through the service layer, which surfaces the
		// backend's own refusal reason (an empty import token, here) rather
		// than a generic "failed to unwrap key" wrapper.
		assert.Contains(t, err.Error(), "import token cannot be empty")
	})
}
