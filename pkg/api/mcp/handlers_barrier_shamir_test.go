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
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-xkms/internal/shamirtest"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestBarrier creates a barrier with ShamirStrategy for testing.
// It wires ceremony and recovery distributors, initializes the barrier,
// and returns the barrier, ceremony distributor, and recovery distributor
// so tests can retrieve share values.
func createTestBarrier(t *testing.T) (*seal.Barrier, *shamirtest.CaptureDistributor, *shamirtest.CaptureDistributor) {
	t.Helper()

	barrierStore := storage.New()

	shamirStrat, err := seal.NewShamirStrategy(2, 3)
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

	dist := shamirtest.New(t)
	recoveryDist := shamirtest.New(t)
	barrier.SetCeremonyDistributor(dist)
	barrier.SetRecoveryDistributor(recoveryDist)

	return barrier, dist, recoveryDist
}

// createTestBarrierServer creates a test server with a barrier attached.
// It injects the XKMSService into Config so the server has full DI.
// Returns the server, ceremony distributor, recovery distributor, and barrier.
func createTestBarrierServer(t *testing.T) (*Server, *shamirtest.CaptureDistributor, *shamirtest.CaptureDistributor, *seal.Barrier) {
	t.Helper()

	svc := setupTestXKMS(t)
	t.Cleanup(cleanupXKMS)

	barrier, dist, recoveryDist := createTestBarrier(t)

	server, err := NewServer(&Config{
		Authenticator: auth.NewNoOpAuthenticator(),
		Barrier:       barrier,
		XKMSService:   svc,
	})
	require.NoError(t, err)

	return server, dist, recoveryDist, barrier
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
		server, _, _, _ := createTestBarrierServer(t)
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
		server, _, _, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		req := makeReq("barrier.initialize", BarrierInitializeParams{Secret: ""})
		_, err := server.handleBarrierInitialize(context.Background(), req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBarrierSecretRequired)
	})

	t.Run("succeeds with valid secret", func(t *testing.T) {
		server, _, _, _ := createTestBarrierServer(t)
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
		server, _, _, _ := createTestBarrierServer(t)
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

	t.Run("succeeds and returns share_count", func(t *testing.T) {
		server, dist, _, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		req := makeReq("barrier.initializeShamir", BarrierInitializeShamirParams{})
		result, err := server.handleBarrierInitializeShamir(context.Background(), req)
		require.NoError(t, err)

		resultMap := result.(map[string]interface{})
		assert.True(t, resultMap["success"].(bool))
		assert.Equal(t, 2, resultMap["threshold"])
		assert.Equal(t, 3, resultMap["total_shares"])
		assert.Equal(t, 3, resultMap["share_count"])

		// Shares are distributed via the ceremony distributor, not returned in response.
		shares := dist.Shares()
		assert.Len(t, shares, 3)
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
		server, _, _, _ := createTestBarrierServer(t)
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
		server, _, _, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		req := makeReq("barrier.unseal", BarrierUnsealParams{Secret: ""})
		_, err := server.handleBarrierUnseal(context.Background(), req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBarrierSecretRequired)
	})

	t.Run("returns error when barrier not initialized", func(t *testing.T) {
		server, _, _, _ := createTestBarrierServer(t)
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
		server, _, _, _ := createTestBarrierServer(t)
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
		server, _, _, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		req := makeReq("barrier.unsealShare", BarrierUnsealShareParams{Share: ""})
		_, err := server.handleBarrierUnsealShare(context.Background(), req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBarrierShareRequired)
	})

	t.Run("submits share and tracks progress", func(t *testing.T) {
		server, dist, _, barrier := createTestBarrierServer(t)
		defer cleanupXKMS()

		// Initialize with Shamir
		initReq := makeReq("barrier.initializeShamir", BarrierInitializeShamirParams{})
		_, err := server.handleBarrierInitializeShamir(context.Background(), initReq)
		require.NoError(t, err)
		shares := dist.Shares()
		require.Len(t, shares, 3)

		// Seal the barrier so we can unseal with shares
		require.NoError(t, barrier.Seal())

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
		server, _, _, _ := createTestBarrierServer(t)
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
		server, _, _, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		req := makeReq("barrier.unsealShares", BarrierUnsealSharesParams{Shares: []string{}})
		_, err := server.handleBarrierUnsealShares(context.Background(), req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBarrierSharesRequired)
	})

	t.Run("succeeds with valid shares", func(t *testing.T) {
		server, dist, _, barrier := createTestBarrierServer(t)
		defer cleanupXKMS()

		// Initialize with Shamir
		initReq := makeReq("barrier.initializeShamir", BarrierInitializeShamirParams{})
		_, err := server.handleBarrierInitializeShamir(context.Background(), initReq)
		require.NoError(t, err)
		shares := dist.Shares()
		require.Len(t, shares, 3)

		// Seal the barrier
		require.NoError(t, barrier.Seal())

		// Batch unseal with threshold shares
		req := makeReq("barrier.unsealShares", BarrierUnsealSharesParams{Shares: shares[:2]})
		result, err := server.handleBarrierUnsealShares(context.Background(), req)
		require.NoError(t, err)

		resultMap := result.(map[string]interface{})
		assert.True(t, resultMap["success"].(bool))
	})
}

// TestBarrierSeal tests the barrier.seal handler.
func TestBarrierSeal(t *testing.T) {
	t.Run("returns error when barrier not configured", func(t *testing.T) {
		server := createTestServer(t)
		defer cleanupXKMS()

		req := makeReq("barrier.seal", nil)
		_, err := server.handleBarrierSeal(context.Background(), req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBarrierNotConfigured)
	})

	t.Run("succeeds on unsealed barrier", func(t *testing.T) {
		server, _, _, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		// Initialize first
		initReq := makeReq("barrier.initializeShamir", BarrierInitializeShamirParams{})
		_, err := server.handleBarrierInitializeShamir(context.Background(), initReq)
		require.NoError(t, err)

		// Seal
		req := makeReq("barrier.seal", nil)
		result, err := server.handleBarrierSeal(context.Background(), req)
		require.NoError(t, err)

		resultMap := result.(map[string]interface{})
		assert.True(t, resultMap["success"].(bool))
		assert.Equal(t, "barrier sealed", resultMap["message"])
	})

	t.Run("idempotent on already sealed barrier", func(t *testing.T) {
		server, _, _, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		// Barrier starts sealed -- sealing again should succeed
		req := makeReq("barrier.seal", nil)
		result, err := server.handleBarrierSeal(context.Background(), req)
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
		_, err := server.handleBarrierStatus(context.Background(), req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBarrierNotConfigured)
	})

	t.Run("returns sealed status before initialization", func(t *testing.T) {
		server, _, _, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		req := makeReq("barrier.status", nil)
		result, err := server.handleBarrierStatus(context.Background(), req)
		require.NoError(t, err)

		resultMap := result.(map[string]interface{})
		assert.True(t, resultMap["sealed"].(bool))
	})

	t.Run("returns unsealed status after initialization", func(t *testing.T) {
		server, _, _, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		// Initialize
		initReq := makeReq("barrier.initializeShamir", BarrierInitializeShamirParams{})
		_, err := server.handleBarrierInitializeShamir(context.Background(), initReq)
		require.NoError(t, err)

		req := makeReq("barrier.status", nil)
		result, err := server.handleBarrierStatus(context.Background(), req)
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
		server, _, _, _ := createTestBarrierServer(t)
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
		server, _, _, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		req := makeReq("barrier.rekey", BarrierRekeyParams{Threshold: 1, Total: 3})
		_, err := server.handleBarrierRekey(context.Background(), req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBarrierThresholdInvalid)
	})

	t.Run("returns error with total less than threshold", func(t *testing.T) {
		server, _, _, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		req := makeReq("barrier.rekey", BarrierRekeyParams{Threshold: 3, Total: 2})
		_, err := server.handleBarrierRekey(context.Background(), req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBarrierTotalInvalid)
	})

	t.Run("succeeds with valid params after initialization", func(t *testing.T) {
		server, dist, _, _ := createTestBarrierServer(t)
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
		assert.Equal(t, 3, resultMap["threshold"])
		assert.Equal(t, 5, resultMap["total_shares"])
		assert.Equal(t, 5, resultMap["share_count"])

		// Shares are distributed via ceremony distributor, not returned in response.
		newShares := dist.Shares()
		assert.Len(t, newShares, 5)
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
		server, _, _, _ := createTestBarrierServer(t)
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
		server, _, _, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		req := makeReq("barrier.generateRecoveryKeys", BarrierGenerateRecoveryKeysParams{Threshold: 1, Total: 3})
		_, err := server.handleBarrierGenerateRecoveryKeys(context.Background(), req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBarrierThresholdInvalid)
	})

	t.Run("returns error with total less than threshold", func(t *testing.T) {
		server, _, _, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		req := makeReq("barrier.generateRecoveryKeys", BarrierGenerateRecoveryKeysParams{Threshold: 3, Total: 2})
		_, err := server.handleBarrierGenerateRecoveryKeys(context.Background(), req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBarrierTotalInvalid)
	})

	t.Run("succeeds after barrier is unsealed", func(t *testing.T) {
		server, _, recoveryDist, _ := createTestBarrierServer(t)
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
		assert.Equal(t, 2, resultMap["threshold"])
		assert.Equal(t, 3, resultMap["total_shares"])
		assert.Equal(t, 3, resultMap["share_count"])

		// Recovery shares are distributed via the recovery distributor, not returned in response.
		recoveryShares := recoveryDist.Shares()
		assert.Len(t, recoveryShares, 3)
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
		server, _, _, _ := createTestBarrierServer(t)
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
		server, _, _, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		req := makeReq("barrier.recoverWithKeys", BarrierRecoverWithKeysParams{Keys: []string{}})
		_, err := server.handleBarrierRecoverWithKeys(context.Background(), req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBarrierRecoveryKeysRequired)
	})

	t.Run("succeeds with valid recovery keys", func(t *testing.T) {
		server, _, recoveryDist, barrier := createTestBarrierServer(t)
		defer cleanupXKMS()

		// Initialize
		initReq := makeReq("barrier.initializeShamir", BarrierInitializeShamirParams{})
		_, err := server.handleBarrierInitializeShamir(context.Background(), initReq)
		require.NoError(t, err)

		// Generate recovery keys; shares captured by recoveryDist
		genReq := makeReq("barrier.generateRecoveryKeys", BarrierGenerateRecoveryKeysParams{Threshold: 2, Total: 3})
		_, err = server.handleBarrierGenerateRecoveryKeys(context.Background(), genReq)
		require.NoError(t, err)
		recoveryShares := recoveryDist.Shares()
		require.Len(t, recoveryShares, 3)

		// Seal the barrier
		require.NoError(t, barrier.Seal())

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
		server, _, _, _ := createTestBarrierServer(t)
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

// TestBarrierHasRecoveryKeys tests the barrier.hasRecoveryKeys handler, which
// reports whether recovery keys have been provisioned. This is the MCP-transport
// peer of the gRPC/unix BarrierHasRecoveryKeys RPC.
func TestBarrierHasRecoveryKeys(t *testing.T) {
	t.Run("returns error when barrier not configured", func(t *testing.T) {
		server := createTestServer(t)
		defer cleanupXKMS()

		req := makeReq("barrier.hasRecoveryKeys", nil)
		_, err := server.handleBarrierHasRecoveryKeys(context.Background(), req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBarrierNotConfigured)
	})

	t.Run("reports false before and true after generating recovery keys", func(t *testing.T) {
		server, _, _, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		// Initialize the barrier.
		initReq := makeReq("barrier.initializeShamir", BarrierInitializeShamirParams{})
		_, err := server.handleBarrierInitializeShamir(context.Background(), initReq)
		require.NoError(t, err)

		// No recovery keys yet.
		beforeReq := makeReq("barrier.hasRecoveryKeys", nil)
		beforeResult, err := server.handleBarrierHasRecoveryKeys(context.Background(), beforeReq)
		require.NoError(t, err)
		assert.False(t, beforeResult.(map[string]interface{})["has_keys"].(bool))

		// Generate recovery keys.
		genReq := makeReq("barrier.generateRecoveryKeys", BarrierGenerateRecoveryKeysParams{Threshold: 2, Total: 3})
		_, err = server.handleBarrierGenerateRecoveryKeys(context.Background(), genReq)
		require.NoError(t, err)

		// Now they are reported as present.
		afterReq := makeReq("barrier.hasRecoveryKeys", nil)
		afterResult, err := server.handleBarrierHasRecoveryKeys(context.Background(), afterReq)
		require.NoError(t, err)
		assert.True(t, afterResult.(map[string]interface{})["has_keys"].(bool))
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
		server, _, _, _ := createTestBarrierServer(t)
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
		server, _, _, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		req := makeReq("barrier.generateRootToken", BarrierGenerateRootTokenParams{Shares: []string{}})
		_, err := server.handleBarrierGenerateRootToken(context.Background(), req)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBarrierSharesRequired)
	})

	t.Run("succeeds with valid shares", func(t *testing.T) {
		server, dist, _, _ := createTestBarrierServer(t)
		defer cleanupXKMS()

		// Initialize with Shamir; shares captured by dist
		initReq := makeReq("barrier.initializeShamir", BarrierInitializeShamirParams{})
		_, err := server.handleBarrierInitializeShamir(context.Background(), initReq)
		require.NoError(t, err)
		shares := dist.Shares()
		require.Len(t, shares, 3)

		// Generate root token using threshold shares
		req := makeReq("barrier.generateRootToken", BarrierGenerateRootTokenParams{Shares: shares[:2]})
		result, err := server.handleBarrierGenerateRootToken(context.Background(), req)
		require.NoError(t, err)

		tokenMap := result.(map[string]interface{})
		assert.True(t, tokenMap["success"].(bool))
		assert.NotEmpty(t, tokenMap["token"])
		assert.NotEmpty(t, tokenMap["created_at"])
	})
}

// TestBarrierMethodRouting tests that barrier methods are properly routed
// through Server.InvokeMethod.
func TestBarrierMethodRouting(t *testing.T) {
	server, _, _, _ := createTestBarrierServer(t)
	defer cleanupXKMS()

	ctx := context.Background()

	t.Run("routes barrier.status", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "barrier.status",
			Params:  json.RawMessage(`{}`),
			ID:      1,
		}
		resp := invokeRequest(server, ctx, req)
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
		resp := invokeRequest(server, ctx, req)
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
		resp := invokeRequest(server, ctx, req)
		require.NotNil(t, resp)
		assert.NotNil(t, resp.Error)
		assert.Equal(t, ErrCodeInternalError, resp.Error.Code)
	})

}

// TestBarrierSetBarrier tests the SetBarrier method.
func TestBarrierSetBarrier(t *testing.T) {
	svc := setupTestXKMS(t)
	defer cleanupXKMS()

	server, err := NewServer(&Config{XKMSService: svc, Authenticator: auth.NewNoOpAuthenticator()})
	require.NoError(t, err)

	// Initially no barrier
	assert.Nil(t, server.barrier)

	// Set barrier
	barrier, _, _ := createTestBarrier(t)
	server.SetBarrier(barrier)
	assert.NotNil(t, server.barrier)

	// Barrier operations should now work
	req := makeReq("barrier.status", nil)
	result, err := server.handleBarrierStatus(context.Background(), req)
	require.NoError(t, err)

	resultMap := result.(map[string]interface{})
	assert.True(t, resultMap["sealed"].(bool))
}

// TestBarrierConfigPassthrough tests that barrier is passed through Config.
func TestBarrierConfigPassthrough(t *testing.T) {
	svc := setupTestXKMS(t)
	defer cleanupXKMS()

	barrier, _, _ := createTestBarrier(t)
	server, err := NewServer(&Config{
		Authenticator: auth.NewNoOpAuthenticator(),
		Barrier:       barrier,
		XKMSService:   svc,
	})
	require.NoError(t, err)
	assert.NotNil(t, server.barrier)
}

// TestBarrierFullLifecycle tests the complete barrier lifecycle through MCP handlers:
// initialize -> status -> seal -> unsealShares -> status -> generate recovery -> seal -> recover
func TestBarrierFullLifecycle(t *testing.T) {
	server, dist, recoveryDist, barrier := createTestBarrierServer(t)
	defer cleanupXKMS()

	ctx := context.Background()

	// 1. Check initial status (sealed)
	statusReq := makeReq("barrier.status", nil)
	statusResult, err := server.handleBarrierStatus(context.Background(), statusReq)
	require.NoError(t, err)
	assert.True(t, statusResult.(map[string]interface{})["sealed"].(bool))

	// 2. Initialize with Shamir; shares captured by dist
	initReq := makeReq("barrier.initializeShamir", BarrierInitializeShamirParams{})
	initResult, err := server.handleBarrierInitializeShamir(ctx, initReq)
	require.NoError(t, err)
	initMap := initResult.(map[string]interface{})
	assert.Equal(t, 3, initMap["share_count"])
	shares := dist.Shares()
	assert.Len(t, shares, 3)

	// 3. Check status (should be unsealed after init)
	statusResult, err = server.handleBarrierStatus(context.Background(), statusReq)
	require.NoError(t, err)
	assert.False(t, statusResult.(map[string]interface{})["sealed"].(bool))

	// 4. Generate recovery keys; recovery shares captured by recoveryDist
	recoveryReq := makeReq("barrier.generateRecoveryKeys", BarrierGenerateRecoveryKeysParams{Threshold: 2, Total: 3})
	_, err = server.handleBarrierGenerateRecoveryKeys(ctx, recoveryReq)
	require.NoError(t, err)
	recoveryShares := recoveryDist.Shares()
	require.Len(t, recoveryShares, 3)

	// 5. Seal the barrier
	sealReq := makeReq("barrier.seal", nil)
	_, err = server.handleBarrierSeal(context.Background(), sealReq)
	require.NoError(t, err)

	// 6. Verify sealed
	statusResult, err = server.handleBarrierStatus(context.Background(), statusReq)
	require.NoError(t, err)
	assert.True(t, statusResult.(map[string]interface{})["sealed"].(bool))

	// 7. Unseal with shares
	unsealReq := makeReq("barrier.unsealShares", BarrierUnsealSharesParams{Shares: shares[:2]})
	_, err = server.handleBarrierUnsealShares(ctx, unsealReq)
	require.NoError(t, err)

	// 8. Verify unsealed
	statusResult, err = server.handleBarrierStatus(context.Background(), statusReq)
	require.NoError(t, err)
	assert.False(t, statusResult.(map[string]interface{})["sealed"].(bool))

	// 9. Rekey with new parameters; new shares captured by dist
	rekeyReq := makeReq("barrier.rekey", BarrierRekeyParams{Threshold: 2, Total: 5})
	rekeyResult, err := server.handleBarrierRekey(ctx, rekeyReq)
	require.NoError(t, err)
	rekeyMap := rekeyResult.(map[string]interface{})
	assert.Equal(t, 5, rekeyMap["share_count"])
	newShares := dist.Shares()
	assert.Len(t, newShares, 5)

	// 10. Seal again
	_, err = server.handleBarrierSeal(context.Background(), sealReq)
	require.NoError(t, err)

	// 11. Recover with recovery keys
	recoverReq := makeReq("barrier.recoverWithKeys", BarrierRecoverWithKeysParams{Keys: recoveryShares[:2]})
	_, err = server.handleBarrierRecoverWithKeys(ctx, recoverReq)
	require.NoError(t, err)

	// 12. Verify unsealed after recovery
	statusResult, err = server.handleBarrierStatus(context.Background(), statusReq)
	require.NoError(t, err)
	assert.False(t, statusResult.(map[string]interface{})["sealed"].(bool))

	// 13. Delete recovery keys
	delRecoveryReq := makeReq("barrier.deleteRecoveryKeys", nil)
	_, err = server.handleBarrierDeleteRecoveryKeys(ctx, delRecoveryReq)
	require.NoError(t, err)

	// 14. Seal and unseal once more with new shares to confirm rekey took effect
	_, err = server.handleBarrierSeal(context.Background(), sealReq)
	require.NoError(t, err)

	unsealNewReq := makeReq("barrier.unsealShares", BarrierUnsealSharesParams{Shares: newShares[:2]})
	_, err = server.handleBarrierUnsealShares(ctx, unsealNewReq)
	require.NoError(t, err)

	// 15. Generate root token using new shares
	tokenReq := makeReq("barrier.generateRootToken", BarrierGenerateRootTokenParams{Shares: newShares[:2]})
	tokenResult, err := server.handleBarrierGenerateRootToken(ctx, tokenReq)
	require.NoError(t, err)

	// Re-seal so the barrier is unsealed for the GenerateRootToken operation —
	// GenerateRootToken reconstructs the master key from shares but does NOT
	// require the barrier to be sealed first.
	_ = barrier
	assert.NotEmpty(t, tokenResult.(map[string]interface{})["token"])
}
