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
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestBarrier creates a barrier with ShamirStrategy for testing.
// It returns the barrier with a 2-of-3 Shamir configuration.
func createTestBarrier(t *testing.T) *seal.Barrier {
	t.Helper()

	barrierStore := storage.New()
	shamirStore := storage.New()

	shamirStrat, err := seal.NewShamirStrategy(shamirStore, 2, 3)
	require.NoError(t, err)

	barrier, err := seal.NewBarrier(
		slog.Default(),
		barrierStore,
		seal.BarrierConfig{
			RootKeyPath: "barrier/root-key",
			Shamir: &seal.ShamirConfig{
				Threshold:   2,
				TotalShares: 3,
			},
		},
		shamirStrat,
	)
	require.NoError(t, err)

	return barrier
}

// createTestBarrierServer creates a test server with a barrier attached.
func createTestBarrierServer(t *testing.T) (*Server, *seal.Barrier) {
	t.Helper()

	setupTestXKMS(t)

	barrier := createTestBarrier(t)

	server, err := NewServer(&Config{
		Addr:    "localhost:0",
		Barrier: barrier,
	})
	require.NoError(t, err)

	return server, barrier
}

// makeReq creates a JSONRPCRequest with the given method and params.
func makeReq(method string, params interface{}) *JSONRPCRequest {
	var paramsJSON json.RawMessage
	if params != nil {
		data, _ := json.Marshal(params)
		paramsJSON = data
	}
	return &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  paramsJSON,
		ID:      1,
	}
}

// TestBarrierInitialize tests the barrier.initialize handler.
func TestBarrierInitialize(t *testing.T) {
	t.Run("returns error when barrier not configured", func(t *testing.T) {
		server := createTestServer(t)
		defer cleanupXKMS()

		req := makeReq("barrier.initialize", BarrierInitializeParams{Secret: "test"})
		_, err := server.handleBarrierInitialize(context.Background(), req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBarrierNotConfigured)
	})

	t.Run("returns error with invalid JSON params", func(t *testing.T) {
		server, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "barrier.initialize",
			Params:  json.RawMessage(`invalid`),
			ID:      1,
		}
		_, err := server.handleBarrierInitialize(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})

	t.Run("returns error with empty secret", func(t *testing.T) {
		server, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		req := makeReq("barrier.initialize", BarrierInitializeParams{Secret: ""})
		_, err := server.handleBarrierInitialize(context.Background(), req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBarrierSecretRequired)
	})

	t.Run("succeeds with valid secret", func(t *testing.T) {
		server, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		req := makeReq("barrier.initialize", BarrierInitializeParams{Secret: "my-secret"})
		result, err := server.handleBarrierInitialize(context.Background(), req)
		require.NoError(t, err)

		resultMap := result.(map[string]interface{})
		assert.True(t, resultMap["success"].(bool))
		assert.Equal(t, "barrier initialized", resultMap["message"])
	})
}

// TestBarrierInitializeShamir tests the barrier.initializeShamir handler.
func TestBarrierInitializeShamir(t *testing.T) {
	t.Run("returns error when barrier not configured", func(t *testing.T) {
		server := createTestServer(t)
		defer cleanupXKMS()

		req := makeReq("barrier.initializeShamir", BarrierInitializeShamirParams{})
		_, err := server.handleBarrierInitializeShamir(context.Background(), req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBarrierNotConfigured)
	})

	t.Run("returns error with invalid JSON params", func(t *testing.T) {
		server, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Params:  json.RawMessage(`not-json`),
			ID:      1,
		}
		_, err := server.handleBarrierInitializeShamir(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})

	t.Run("succeeds and returns shares", func(t *testing.T) {
		server, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		req := makeReq("barrier.initializeShamir", BarrierInitializeShamirParams{})
		result, err := server.handleBarrierInitializeShamir(context.Background(), req)
		require.NoError(t, err)

		resultMap := result.(map[string]interface{})
		assert.True(t, resultMap["success"].(bool))

		shares, ok := resultMap["shares"].([]string)
		require.True(t, ok)
		assert.Len(t, shares, 3)
		assert.Equal(t, 2, resultMap["threshold"])
		assert.Equal(t, 3, resultMap["total_shares"])
	})
}

// TestBarrierUnseal tests the barrier.unseal handler.
func TestBarrierUnseal(t *testing.T) {
	t.Run("returns error when barrier not configured", func(t *testing.T) {
		server := createTestServer(t)
		defer cleanupXKMS()

		req := makeReq("barrier.unseal", BarrierUnsealParams{Secret: "test"})
		_, err := server.handleBarrierUnseal(context.Background(), req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBarrierNotConfigured)
	})

	t.Run("returns error with invalid JSON params", func(t *testing.T) {
		server, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Params:  json.RawMessage(`bad`),
			ID:      1,
		}
		_, err := server.handleBarrierUnseal(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})

	t.Run("returns error with empty secret", func(t *testing.T) {
		server, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		req := makeReq("barrier.unseal", BarrierUnsealParams{Secret: ""})
		_, err := server.handleBarrierUnseal(context.Background(), req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBarrierSecretRequired)
	})

	t.Run("returns error when barrier not initialized", func(t *testing.T) {
		server, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		req := makeReq("barrier.unseal", BarrierUnsealParams{Secret: "secret"})
		_, err := server.handleBarrierUnseal(context.Background(), req)
		require.Error(t, err)
	})
}

// TestBarrierUnsealShare tests the barrier.unsealShare handler.
func TestBarrierUnsealShare(t *testing.T) {
	t.Run("returns error when barrier not configured", func(t *testing.T) {
		server := createTestServer(t)
		defer cleanupXKMS()

		req := makeReq("barrier.unsealShare", BarrierUnsealShareParams{Share: "abc"})
		_, err := server.handleBarrierUnsealShare(context.Background(), req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBarrierNotConfigured)
	})

	t.Run("returns error with invalid JSON params", func(t *testing.T) {
		server, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Params:  json.RawMessage(`???`),
			ID:      1,
		}
		_, err := server.handleBarrierUnsealShare(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})

	t.Run("returns error with empty share", func(t *testing.T) {
		server, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		req := makeReq("barrier.unsealShare", BarrierUnsealShareParams{Share: ""})
		_, err := server.handleBarrierUnsealShare(context.Background(), req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBarrierShareRequired)
	})

	t.Run("submits share and tracks progress", func(t *testing.T) {
		server, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		// First initialize with Shamir
		initReq := makeReq("barrier.initializeShamir", BarrierInitializeShamirParams{})
		initResult, err := server.handleBarrierInitializeShamir(context.Background(), initReq)
		require.NoError(t, err)

		resultMap := initResult.(map[string]interface{})
		shares := resultMap["shares"].([]string)

		// Seal the barrier so we can unseal with shares
		sealReq := makeReq("barrier.seal", nil)
		_, err = server.handleBarrierSeal(sealReq)
		require.NoError(t, err)

		// Submit first share
		req := makeReq("barrier.unsealShare", BarrierUnsealShareParams{Share: shares[0]})
		result, err := server.handleBarrierUnsealShare(context.Background(), req)
		require.NoError(t, err)

		progressMap := result.(map[string]interface{})
		assert.Equal(t, 2, progressMap["required"])
		assert.Equal(t, 1, progressMap["submitted"])
		assert.False(t, progressMap["complete"].(bool))

		// Submit second share -- reaches threshold
		req2 := makeReq("barrier.unsealShare", BarrierUnsealShareParams{Share: shares[1]})
		result2, err := server.handleBarrierUnsealShare(context.Background(), req2)
		require.NoError(t, err)

		progressMap2 := result2.(map[string]interface{})
		assert.Equal(t, 2, progressMap2["required"])
		assert.Equal(t, 2, progressMap2["submitted"])
		assert.True(t, progressMap2["complete"].(bool))
	})
}

// TestBarrierUnsealShares tests the barrier.unsealShares handler.
func TestBarrierUnsealShares(t *testing.T) {
	t.Run("returns error when barrier not configured", func(t *testing.T) {
		server := createTestServer(t)
		defer cleanupXKMS()

		req := makeReq("barrier.unsealShares", BarrierUnsealSharesParams{Shares: []string{"a", "b"}})
		_, err := server.handleBarrierUnsealShares(context.Background(), req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBarrierNotConfigured)
	})

	t.Run("returns error with invalid JSON params", func(t *testing.T) {
		server, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Params:  json.RawMessage(`{bad}`),
			ID:      1,
		}
		_, err := server.handleBarrierUnsealShares(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})

	t.Run("returns error with empty shares", func(t *testing.T) {
		server, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		req := makeReq("barrier.unsealShares", BarrierUnsealSharesParams{Shares: []string{}})
		_, err := server.handleBarrierUnsealShares(context.Background(), req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBarrierSharesRequired)
	})

	t.Run("succeeds with valid shares", func(t *testing.T) {
		server, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		// Initialize with Shamir
		initReq := makeReq("barrier.initializeShamir", BarrierInitializeShamirParams{})
		initResult, err := server.handleBarrierInitializeShamir(context.Background(), initReq)
		require.NoError(t, err)

		resultMap := initResult.(map[string]interface{})
		shares := resultMap["shares"].([]string)

		// Seal the barrier
		sealReq := makeReq("barrier.seal", nil)
		_, err = server.handleBarrierSeal(sealReq)
		require.NoError(t, err)

		// Batch unseal with all shares
		req := makeReq("barrier.unsealShares", BarrierUnsealSharesParams{Shares: shares[:2]})
		result, err := server.handleBarrierUnsealShares(context.Background(), req)
		require.NoError(t, err)

		resultMap2 := result.(map[string]interface{})
		assert.True(t, resultMap2["success"].(bool))
	})
}

// TestBarrierSeal tests the barrier.seal handler.
func TestBarrierSeal(t *testing.T) {
	t.Run("returns error when barrier not configured", func(t *testing.T) {
		server := createTestServer(t)
		defer cleanupXKMS()

		req := makeReq("barrier.seal", nil)
		_, err := server.handleBarrierSeal(req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBarrierNotConfigured)
	})

	t.Run("succeeds on unsealed barrier", func(t *testing.T) {
		server, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		// Initialize first
		initReq := makeReq("barrier.initializeShamir", BarrierInitializeShamirParams{})
		_, err := server.handleBarrierInitializeShamir(context.Background(), initReq)
		require.NoError(t, err)

		// Seal
		req := makeReq("barrier.seal", nil)
		result, err := server.handleBarrierSeal(req)
		require.NoError(t, err)

		resultMap := result.(map[string]interface{})
		assert.True(t, resultMap["success"].(bool))
		assert.Equal(t, "barrier sealed", resultMap["message"])
	})

	t.Run("idempotent on already sealed barrier", func(t *testing.T) {
		server, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		// Barrier starts sealed -- sealing again should succeed
		req := makeReq("barrier.seal", nil)
		result, err := server.handleBarrierSeal(req)
		require.NoError(t, err)

		resultMap := result.(map[string]interface{})
		assert.True(t, resultMap["success"].(bool))
	})
}

// TestBarrierStatus tests the barrier.status handler.
func TestBarrierStatus(t *testing.T) {
	t.Run("returns error when barrier not configured", func(t *testing.T) {
		server := createTestServer(t)
		defer cleanupXKMS()

		req := makeReq("barrier.status", nil)
		_, err := server.handleBarrierStatus(req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBarrierNotConfigured)
	})

	t.Run("returns sealed status before initialization", func(t *testing.T) {
		server, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		req := makeReq("barrier.status", nil)
		result, err := server.handleBarrierStatus(req)
		require.NoError(t, err)

		resultMap := result.(map[string]interface{})
		assert.True(t, resultMap["sealed"].(bool))
	})

	t.Run("returns unsealed status after initialization", func(t *testing.T) {
		server, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		// Initialize
		initReq := makeReq("barrier.initializeShamir", BarrierInitializeShamirParams{})
		_, err := server.handleBarrierInitializeShamir(context.Background(), initReq)
		require.NoError(t, err)

		req := makeReq("barrier.status", nil)
		result, err := server.handleBarrierStatus(req)
		require.NoError(t, err)

		resultMap := result.(map[string]interface{})
		assert.False(t, resultMap["sealed"].(bool))
		assert.Equal(t, "shamir", resultMap["strategy"])
		assert.False(t, resultMap["hardware_backed"].(bool))
	})
}

// TestBarrierRekey tests the barrier.rekey handler.
func TestBarrierRekey(t *testing.T) {
	t.Run("returns error when barrier not configured", func(t *testing.T) {
		server := createTestServer(t)
		defer cleanupXKMS()

		req := makeReq("barrier.rekey", BarrierRekeyParams{Threshold: 2, Total: 3})
		_, err := server.handleBarrierRekey(context.Background(), req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBarrierNotConfigured)
	})

	t.Run("returns error with invalid JSON params", func(t *testing.T) {
		server, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Params:  json.RawMessage(`blah`),
			ID:      1,
		}
		_, err := server.handleBarrierRekey(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})

	t.Run("returns error with threshold less than 2", func(t *testing.T) {
		server, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		req := makeReq("barrier.rekey", BarrierRekeyParams{Threshold: 1, Total: 3})
		_, err := server.handleBarrierRekey(context.Background(), req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBarrierThresholdInvalid)
	})

	t.Run("returns error with total less than threshold", func(t *testing.T) {
		server, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		req := makeReq("barrier.rekey", BarrierRekeyParams{Threshold: 3, Total: 2})
		_, err := server.handleBarrierRekey(context.Background(), req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBarrierTotalInvalid)
	})

	t.Run("succeeds with valid params after initialization", func(t *testing.T) {
		server, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		// Initialize first
		initReq := makeReq("barrier.initializeShamir", BarrierInitializeShamirParams{})
		_, err := server.handleBarrierInitializeShamir(context.Background(), initReq)
		require.NoError(t, err)

		// Rekey with new parameters
		req := makeReq("barrier.rekey", BarrierRekeyParams{Threshold: 3, Total: 5})
		result, err := server.handleBarrierRekey(context.Background(), req)
		require.NoError(t, err)

		resultMap := result.(map[string]interface{})
		assert.True(t, resultMap["success"].(bool))
		shares := resultMap["shares"].([]string)
		assert.Len(t, shares, 5)
		assert.Equal(t, 3, resultMap["threshold"])
		assert.Equal(t, 5, resultMap["total_shares"])
	})
}

// TestBarrierShamirListShares tests the barrier.shamirListShares handler.
func TestBarrierShamirListShares(t *testing.T) {
	t.Run("returns error when barrier not configured", func(t *testing.T) {
		server := createTestServer(t)
		defer cleanupXKMS()

		req := makeReq("barrier.shamirListShares", nil)
		_, err := server.handleBarrierShamirListShares(context.Background(), req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBarrierNotConfigured)
	})

	t.Run("returns share count and config after init", func(t *testing.T) {
		server, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		// Initialize
		initReq := makeReq("barrier.initializeShamir", BarrierInitializeShamirParams{})
		_, err := server.handleBarrierInitializeShamir(context.Background(), initReq)
		require.NoError(t, err)

		req := makeReq("barrier.shamirListShares", nil)
		result, err := server.handleBarrierShamirListShares(context.Background(), req)
		require.NoError(t, err)

		resultMap := result.(map[string]interface{})
		assert.Equal(t, 3, resultMap["count"])
		assert.Equal(t, 2, resultMap["threshold"])
		assert.Equal(t, 3, resultMap["total"])
	})
}

// TestBarrierShamirDeleteShare tests the barrier.shamirDeleteShare handler.
func TestBarrierShamirDeleteShare(t *testing.T) {
	t.Run("returns error when barrier not configured", func(t *testing.T) {
		server := createTestServer(t)
		defer cleanupXKMS()

		req := makeReq("barrier.shamirDeleteShare", BarrierShamirDeleteShareParams{Index: 1})
		_, err := server.handleBarrierShamirDeleteShare(context.Background(), req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBarrierNotConfigured)
	})

	t.Run("returns error with invalid JSON params", func(t *testing.T) {
		server, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Params:  json.RawMessage(`nope`),
			ID:      1,
		}
		_, err := server.handleBarrierShamirDeleteShare(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})

	t.Run("returns error with invalid index", func(t *testing.T) {
		server, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		req := makeReq("barrier.shamirDeleteShare", BarrierShamirDeleteShareParams{Index: 0})
		_, err := server.handleBarrierShamirDeleteShare(context.Background(), req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBarrierShareIndexInvalid)
	})

	t.Run("succeeds deleting a share after initialization", func(t *testing.T) {
		server, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		// Initialize
		initReq := makeReq("barrier.initializeShamir", BarrierInitializeShamirParams{})
		_, err := server.handleBarrierInitializeShamir(context.Background(), initReq)
		require.NoError(t, err)

		// Delete share 1
		req := makeReq("barrier.shamirDeleteShare", BarrierShamirDeleteShareParams{Index: 1})
		result, err := server.handleBarrierShamirDeleteShare(context.Background(), req)
		require.NoError(t, err)

		resultMap := result.(map[string]interface{})
		assert.True(t, resultMap["success"].(bool))
		assert.Contains(t, resultMap["message"], "share 1 deleted")
	})
}

// TestBarrierShamirDeleteAllShares tests the barrier.shamirDeleteAllShares handler.
func TestBarrierShamirDeleteAllShares(t *testing.T) {
	t.Run("returns error when barrier not configured", func(t *testing.T) {
		server := createTestServer(t)
		defer cleanupXKMS()

		req := makeReq("barrier.shamirDeleteAllShares", nil)
		_, err := server.handleBarrierShamirDeleteAllShares(context.Background(), req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBarrierNotConfigured)
	})

	t.Run("succeeds deleting all shares after initialization", func(t *testing.T) {
		server, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		// Initialize
		initReq := makeReq("barrier.initializeShamir", BarrierInitializeShamirParams{})
		_, err := server.handleBarrierInitializeShamir(context.Background(), initReq)
		require.NoError(t, err)

		// Delete all shares
		req := makeReq("barrier.shamirDeleteAllShares", nil)
		result, err := server.handleBarrierShamirDeleteAllShares(context.Background(), req)
		require.NoError(t, err)

		resultMap := result.(map[string]interface{})
		assert.True(t, resultMap["success"].(bool))
		assert.Equal(t, "all shares deleted", resultMap["message"])

		// Verify no shares remain
		listReq := makeReq("barrier.shamirListShares", nil)
		listResult, err := server.handleBarrierShamirListShares(context.Background(), listReq)
		require.NoError(t, err)

		listMap := listResult.(map[string]interface{})
		assert.Equal(t, 0, listMap["count"])
	})
}

// TestBarrierShamirVerify tests the barrier.shamirVerify handler.
func TestBarrierShamirVerify(t *testing.T) {
	t.Run("returns error when barrier not configured", func(t *testing.T) {
		server := createTestServer(t)
		defer cleanupXKMS()

		req := makeReq("barrier.shamirVerify", nil)
		_, err := server.handleBarrierShamirVerify(context.Background(), req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBarrierNotConfigured)
	})

	t.Run("succeeds when shares are valid", func(t *testing.T) {
		server, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		// Initialize
		initReq := makeReq("barrier.initializeShamir", BarrierInitializeShamirParams{})
		_, err := server.handleBarrierInitializeShamir(context.Background(), initReq)
		require.NoError(t, err)

		// Verify shares
		req := makeReq("barrier.shamirVerify", nil)
		result, err := server.handleBarrierShamirVerify(context.Background(), req)
		require.NoError(t, err)

		resultMap := result.(map[string]interface{})
		assert.True(t, resultMap["success"].(bool))
		assert.Equal(t, "shares verified successfully", resultMap["message"])
	})
}

// TestBarrierGenerateRecoveryKeys tests the barrier.generateRecoveryKeys handler.
func TestBarrierGenerateRecoveryKeys(t *testing.T) {
	t.Run("returns error when barrier not configured", func(t *testing.T) {
		server := createTestServer(t)
		defer cleanupXKMS()

		req := makeReq("barrier.generateRecoveryKeys", BarrierGenerateRecoveryKeysParams{Threshold: 2, Total: 3})
		_, err := server.handleBarrierGenerateRecoveryKeys(context.Background(), req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBarrierNotConfigured)
	})

	t.Run("returns error with invalid JSON params", func(t *testing.T) {
		server, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Params:  json.RawMessage(`bad-json`),
			ID:      1,
		}
		_, err := server.handleBarrierGenerateRecoveryKeys(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})

	t.Run("returns error with threshold less than 2", func(t *testing.T) {
		server, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		req := makeReq("barrier.generateRecoveryKeys", BarrierGenerateRecoveryKeysParams{Threshold: 1, Total: 3})
		_, err := server.handleBarrierGenerateRecoveryKeys(context.Background(), req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBarrierThresholdInvalid)
	})

	t.Run("returns error with total less than threshold", func(t *testing.T) {
		server, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		req := makeReq("barrier.generateRecoveryKeys", BarrierGenerateRecoveryKeysParams{Threshold: 3, Total: 2})
		_, err := server.handleBarrierGenerateRecoveryKeys(context.Background(), req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBarrierTotalInvalid)
	})

	t.Run("succeeds after barrier is unsealed", func(t *testing.T) {
		server, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		// Initialize first
		initReq := makeReq("barrier.initializeShamir", BarrierInitializeShamirParams{})
		_, err := server.handleBarrierInitializeShamir(context.Background(), initReq)
		require.NoError(t, err)

		// Generate recovery keys
		req := makeReq("barrier.generateRecoveryKeys", BarrierGenerateRecoveryKeysParams{Threshold: 2, Total: 3})
		result, err := server.handleBarrierGenerateRecoveryKeys(context.Background(), req)
		require.NoError(t, err)

		resultMap := result.(map[string]interface{})
		assert.True(t, resultMap["success"].(bool))
		shares := resultMap["shares"].([]string)
		assert.Len(t, shares, 3)
		assert.Equal(t, 2, resultMap["threshold"])
		assert.Equal(t, 3, resultMap["total_shares"])
	})
}

// TestBarrierRecoverWithKeys tests the barrier.recoverWithKeys handler.
func TestBarrierRecoverWithKeys(t *testing.T) {
	t.Run("returns error when barrier not configured", func(t *testing.T) {
		server := createTestServer(t)
		defer cleanupXKMS()

		req := makeReq("barrier.recoverWithKeys", BarrierRecoverWithKeysParams{Keys: []string{"a"}})
		_, err := server.handleBarrierRecoverWithKeys(context.Background(), req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBarrierNotConfigured)
	})

	t.Run("returns error with invalid JSON params", func(t *testing.T) {
		server, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Params:  json.RawMessage(`oops`),
			ID:      1,
		}
		_, err := server.handleBarrierRecoverWithKeys(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})

	t.Run("returns error with empty keys", func(t *testing.T) {
		server, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		req := makeReq("barrier.recoverWithKeys", BarrierRecoverWithKeysParams{Keys: []string{}})
		_, err := server.handleBarrierRecoverWithKeys(context.Background(), req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBarrierRecoveryKeysRequired)
	})

	t.Run("succeeds with valid recovery keys", func(t *testing.T) {
		server, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		// Initialize
		initReq := makeReq("barrier.initializeShamir", BarrierInitializeShamirParams{})
		_, err := server.handleBarrierInitializeShamir(context.Background(), initReq)
		require.NoError(t, err)

		// Generate recovery keys
		genReq := makeReq("barrier.generateRecoveryKeys", BarrierGenerateRecoveryKeysParams{Threshold: 2, Total: 3})
		genResult, err := server.handleBarrierGenerateRecoveryKeys(context.Background(), genReq)
		require.NoError(t, err)

		genMap := genResult.(map[string]interface{})
		recoveryShares := genMap["shares"].([]string)

		// Seal the barrier
		sealReq := makeReq("barrier.seal", nil)
		_, err = server.handleBarrierSeal(sealReq)
		require.NoError(t, err)

		// Recover with recovery keys
		req := makeReq("barrier.recoverWithKeys", BarrierRecoverWithKeysParams{Keys: recoveryShares[:2]})
		result, err := server.handleBarrierRecoverWithKeys(context.Background(), req)
		require.NoError(t, err)

		resultMap := result.(map[string]interface{})
		assert.True(t, resultMap["success"].(bool))
	})
}

// TestBarrierDeleteRecoveryKeys tests the barrier.deleteRecoveryKeys handler.
func TestBarrierDeleteRecoveryKeys(t *testing.T) {
	t.Run("returns error when barrier not configured", func(t *testing.T) {
		server := createTestServer(t)
		defer cleanupXKMS()

		req := makeReq("barrier.deleteRecoveryKeys", nil)
		_, err := server.handleBarrierDeleteRecoveryKeys(context.Background(), req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBarrierNotConfigured)
	})

	t.Run("succeeds after generating recovery keys", func(t *testing.T) {
		server, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		// Initialize
		initReq := makeReq("barrier.initializeShamir", BarrierInitializeShamirParams{})
		_, err := server.handleBarrierInitializeShamir(context.Background(), initReq)
		require.NoError(t, err)

		// Generate recovery keys
		genReq := makeReq("barrier.generateRecoveryKeys", BarrierGenerateRecoveryKeysParams{Threshold: 2, Total: 3})
		_, err = server.handleBarrierGenerateRecoveryKeys(context.Background(), genReq)
		require.NoError(t, err)

		// Delete recovery keys
		req := makeReq("barrier.deleteRecoveryKeys", nil)
		result, err := server.handleBarrierDeleteRecoveryKeys(context.Background(), req)
		require.NoError(t, err)

		resultMap := result.(map[string]interface{})
		assert.True(t, resultMap["success"].(bool))
		assert.Equal(t, "recovery keys deleted", resultMap["message"])
	})
}

// TestBarrierGenerateRootToken tests the barrier.generateRootToken handler.
func TestBarrierGenerateRootToken(t *testing.T) {
	t.Run("returns error when barrier not configured", func(t *testing.T) {
		server := createTestServer(t)
		defer cleanupXKMS()

		req := makeReq("barrier.generateRootToken", BarrierGenerateRootTokenParams{Shares: []string{"a"}})
		_, err := server.handleBarrierGenerateRootToken(context.Background(), req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBarrierNotConfigured)
	})

	t.Run("returns error with invalid JSON params", func(t *testing.T) {
		server, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Params:  json.RawMessage(`!!!`),
			ID:      1,
		}
		_, err := server.handleBarrierGenerateRootToken(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})

	t.Run("returns error with empty shares", func(t *testing.T) {
		server, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		req := makeReq("barrier.generateRootToken", BarrierGenerateRootTokenParams{Shares: []string{}})
		_, err := server.handleBarrierGenerateRootToken(context.Background(), req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBarrierSharesRequired)
	})

	t.Run("succeeds with valid shares", func(t *testing.T) {
		server, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		// Initialize with Shamir
		initReq := makeReq("barrier.initializeShamir", BarrierInitializeShamirParams{})
		initResult, err := server.handleBarrierInitializeShamir(context.Background(), initReq)
		require.NoError(t, err)

		resultMap := initResult.(map[string]interface{})
		shares := resultMap["shares"].([]string)

		// Generate root token
		req := makeReq("barrier.generateRootToken", BarrierGenerateRootTokenParams{Shares: shares[:2]})
		result, err := server.handleBarrierGenerateRootToken(context.Background(), req)
		require.NoError(t, err)

		tokenMap := result.(map[string]interface{})
		assert.True(t, tokenMap["success"].(bool))
		assert.NotEmpty(t, tokenMap["token"])
		assert.NotEmpty(t, tokenMap["created_at"])
	})
}

// TestBarrierShamirNotConfiguredForNonShamirBarrier tests that Shamir-specific operations
// return the correct error when the barrier has no Shamir strategy registered.
func TestBarrierShamirNotConfiguredForNonShamirBarrier(t *testing.T) {
	setupTestXKMS(t)
	defer cleanupXKMS()

	// Create a barrier without a Shamir strategy (software-only strategy would be used,
	// but we just need any barrier without a ShamirStrategy registered).
	barrierStore := storage.New()

	softwareStrat := seal.NewSoftwareStrategy()
	barrier, err := seal.NewBarrier(
		slog.Default(),
		barrierStore,
		seal.BarrierConfig{
			RootKeyPath: "barrier/root-key",
		},
		softwareStrat,
	)
	require.NoError(t, err)

	server, err := NewServer(&Config{
		Addr:    "localhost:0",
		Barrier: barrier,
	})
	require.NoError(t, err)

	t.Run("shamirListShares returns shamir not configured", func(t *testing.T) {
		req := makeReq("barrier.shamirListShares", nil)
		_, err := server.handleBarrierShamirListShares(context.Background(), req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBarrierShamirNotConfigured)
	})

	t.Run("shamirDeleteShare returns shamir not configured", func(t *testing.T) {
		req := makeReq("barrier.shamirDeleteShare", BarrierShamirDeleteShareParams{Index: 1})
		_, err := server.handleBarrierShamirDeleteShare(context.Background(), req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBarrierShamirNotConfigured)
	})

	t.Run("shamirDeleteAllShares returns shamir not configured", func(t *testing.T) {
		req := makeReq("barrier.shamirDeleteAllShares", nil)
		_, err := server.handleBarrierShamirDeleteAllShares(context.Background(), req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBarrierShamirNotConfigured)
	})

	t.Run("shamirVerify returns shamir not configured", func(t *testing.T) {
		req := makeReq("barrier.shamirVerify", nil)
		_, err := server.handleBarrierShamirVerify(context.Background(), req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBarrierShamirNotConfigured)
	})
}

// TestBarrierMethodRouting tests that barrier methods are properly routed
// through handleRequest.
func TestBarrierMethodRouting(t *testing.T) {
	server, _ := createTestBarrierServer(t)
	defer cleanupXKMS()

	ctx := context.Background()

	t.Run("routes barrier.status", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "barrier.status",
			Params:  json.RawMessage(`{}`),
			ID:      1,
		}
		resp := server.handleRequest(ctx, req, nil)
		require.NotNil(t, resp)
		assert.Nil(t, resp.Error)
	})

	t.Run("routes barrier.seal", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "barrier.seal",
			Params:  json.RawMessage(`{}`),
			ID:      2,
		}
		resp := server.handleRequest(ctx, req, nil)
		require.NotNil(t, resp)
		assert.Nil(t, resp.Error)
	})

	t.Run("routes barrier.initialize with error for missing secret", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "barrier.initialize",
			Params:  json.RawMessage(`{"secret":""}`),
			ID:      3,
		}
		resp := server.handleRequest(ctx, req, nil)
		require.NotNil(t, resp)
		assert.NotNil(t, resp.Error)
		assert.Equal(t, ErrCodeInternalError, resp.Error.Code)
	})

	t.Run("routes barrier.shamirListShares", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "barrier.shamirListShares",
			Params:  json.RawMessage(`{}`),
			ID:      4,
		}
		resp := server.handleRequest(ctx, req, nil)
		require.NotNil(t, resp)
		// This should succeed because Shamir strategy is registered
		assert.Nil(t, resp.Error)
	})
}

// TestBarrierSetBarrier tests the SetBarrier method.
func TestBarrierSetBarrier(t *testing.T) {
	setupTestXKMS(t)
	defer cleanupXKMS()

	server, err := NewServer(&Config{Addr: "localhost:0"})
	require.NoError(t, err)

	// Initially no barrier
	assert.Nil(t, server.barrier)

	// Set barrier
	barrier := createTestBarrier(t)
	server.SetBarrier(barrier)
	assert.NotNil(t, server.barrier)

	// Barrier operations should now work
	req := makeReq("barrier.status", nil)
	result, err := server.handleBarrierStatus(req)
	require.NoError(t, err)

	resultMap := result.(map[string]interface{})
	assert.True(t, resultMap["sealed"].(bool))
}

// TestBarrierConfigPassthrough tests that barrier is passed through Config.
func TestBarrierConfigPassthrough(t *testing.T) {
	setupTestXKMS(t)
	defer cleanupXKMS()

	barrier := createTestBarrier(t)
	server, err := NewServer(&Config{
		Addr:    "localhost:0",
		Barrier: barrier,
	})
	require.NoError(t, err)
	assert.NotNil(t, server.barrier)
}

// TestBarrierFullLifecycle tests the complete barrier lifecycle through MCP handlers:
// initialize -> status -> seal -> unsealShares -> status -> generate recovery -> seal -> recover
func TestBarrierFullLifecycle(t *testing.T) {
	server, _ := createTestBarrierServer(t)
	defer cleanupXKMS()

	ctx := context.Background()

	// 1. Check initial status (sealed)
	statusReq := makeReq("barrier.status", nil)
	statusResult, err := server.handleBarrierStatus(statusReq)
	require.NoError(t, err)
	assert.True(t, statusResult.(map[string]interface{})["sealed"].(bool))

	// 2. Initialize with Shamir
	initReq := makeReq("barrier.initializeShamir", BarrierInitializeShamirParams{})
	initResult, err := server.handleBarrierInitializeShamir(ctx, initReq)
	require.NoError(t, err)
	initMap := initResult.(map[string]interface{})
	shares := initMap["shares"].([]string)
	assert.Len(t, shares, 3)

	// 3. Check status (should be unsealed after init)
	statusResult, err = server.handleBarrierStatus(statusReq)
	require.NoError(t, err)
	assert.False(t, statusResult.(map[string]interface{})["sealed"].(bool))

	// 4. List shares
	listReq := makeReq("barrier.shamirListShares", nil)
	listResult, err := server.handleBarrierShamirListShares(ctx, listReq)
	require.NoError(t, err)
	assert.Equal(t, 3, listResult.(map[string]interface{})["count"])

	// 5. Verify shares
	verifyReq := makeReq("barrier.shamirVerify", nil)
	_, err = server.handleBarrierShamirVerify(ctx, verifyReq)
	require.NoError(t, err)

	// 6. Generate recovery keys
	recoveryReq := makeReq("barrier.generateRecoveryKeys", BarrierGenerateRecoveryKeysParams{Threshold: 2, Total: 3})
	recoveryResult, err := server.handleBarrierGenerateRecoveryKeys(ctx, recoveryReq)
	require.NoError(t, err)
	recoveryShares := recoveryResult.(map[string]interface{})["shares"].([]string)

	// 7. Seal the barrier
	sealReq := makeReq("barrier.seal", nil)
	_, err = server.handleBarrierSeal(sealReq)
	require.NoError(t, err)

	// 8. Verify sealed
	statusResult, err = server.handleBarrierStatus(statusReq)
	require.NoError(t, err)
	assert.True(t, statusResult.(map[string]interface{})["sealed"].(bool))

	// 9. Unseal with shares
	unsealReq := makeReq("barrier.unsealShares", BarrierUnsealSharesParams{Shares: shares[:2]})
	_, err = server.handleBarrierUnsealShares(ctx, unsealReq)
	require.NoError(t, err)

	// 10. Verify unsealed
	statusResult, err = server.handleBarrierStatus(statusReq)
	require.NoError(t, err)
	assert.False(t, statusResult.(map[string]interface{})["sealed"].(bool))

	// 11. Rekey with new parameters
	rekeyReq := makeReq("barrier.rekey", BarrierRekeyParams{Threshold: 2, Total: 5})
	rekeyResult, err := server.handleBarrierRekey(ctx, rekeyReq)
	require.NoError(t, err)
	newShares := rekeyResult.(map[string]interface{})["shares"].([]string)
	assert.Len(t, newShares, 5)

	// 12. Seal again
	_, err = server.handleBarrierSeal(sealReq)
	require.NoError(t, err)

	// 13. Recover with recovery keys
	recoverReq := makeReq("barrier.recoverWithKeys", BarrierRecoverWithKeysParams{Keys: recoveryShares[:2]})
	_, err = server.handleBarrierRecoverWithKeys(ctx, recoverReq)
	require.NoError(t, err)

	// 14. Verify unsealed after recovery
	statusResult, err = server.handleBarrierStatus(statusReq)
	require.NoError(t, err)
	assert.False(t, statusResult.(map[string]interface{})["sealed"].(bool))

	// 15. Delete recovery keys
	delRecoveryReq := makeReq("barrier.deleteRecoveryKeys", nil)
	_, err = server.handleBarrierDeleteRecoveryKeys(ctx, delRecoveryReq)
	require.NoError(t, err)

	// 16. Generate root token
	tokenReq := makeReq("barrier.generateRootToken", BarrierGenerateRootTokenParams{Shares: newShares[:2]})
	tokenResult, err := server.handleBarrierGenerateRootToken(ctx, tokenReq)
	require.NoError(t, err)
	assert.NotEmpty(t, tokenResult.(map[string]interface{})["token"])
}
