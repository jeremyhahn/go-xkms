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

package rest

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/internal/shamirtest"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testShamirBarrierContext creates a HandlerContext with a Shamir-configured barrier
// using in-memory storage. The barrier is returned so tests can manipulate state.
func testShamirBarrierContext(t *testing.T) (*HandlerContext, *seal.Barrier) {
	t.Helper()

	store := storage.NewMemory()
	shamirStrat, err := seal.NewShamirStrategy(2, 3)
	require.NoError(t, err)

	barrier, err := seal.NewBarrier(
		slog.Default(),
		store,
		seal.BarrierConfig{
			RootKeyPath: "test-root-key",
			Shamir:      &seal.ShamirConfig{Threshold: 2, TotalShares: 3},
		},
		shamirStrat,
	)
	require.NoError(t, err)

	h := handlerOverBarrier(barrier)
	return h, barrier
}

// initializeShamirBarrier is a test helper that wires a captureDistributor,
// initializes the Shamir barrier, and returns the generated share strings so
// tests can call UnsealWithShare / UnsealWithShares with real share values.
func initializeShamirBarrier(t *testing.T, barrier *seal.Barrier) []string {
	t.Helper()

	dist := shamirtest.New(t)
	barrier.SetCeremonyDistributor(dist)
	_, err := barrier.InitializeShamir(context.Background(), seal.Credentials{})
	require.NoError(t, err)
	shares := dist.Shares()
	require.Len(t, shares, 3)
	return shares
}

// --- BarrierInitializeShamirHandler ---

func TestBarrierInitializeShamirHandler(t *testing.T) {
	t.Run("initializes barrier with shamir shares", func(t *testing.T) {
		h, barrier := testShamirBarrierContext(t)
		dist := shamirtest.New(t)
		barrier.SetCeremonyDistributor(dist)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/initialize-shamir",
			strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		h.BarrierInitializeShamirHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp struct {
			Threshold   int `json:"threshold"`
			TotalShares int `json:"total_shares"`
			ShareCount  int `json:"share_count"`
		}
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, 3, resp.ShareCount)
		assert.Equal(t, 2, resp.Threshold)
		assert.Equal(t, 3, resp.TotalShares)
	})

	t.Run("returns 503 when barrier is nil", func(t *testing.T) {
		h := NewHandlerContext("test")

		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/initialize-shamir",
			strings.NewReader(`{}`))
		w := httptest.NewRecorder()

		h.BarrierInitializeShamirHandler(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("returns 400 for invalid JSON", func(t *testing.T) {
		h, _ := testShamirBarrierContext(t)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/initialize-shamir",
			strings.NewReader(`{invalid`))
		w := httptest.NewRecorder()

		h.BarrierInitializeShamirHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns conflict when already initialized", func(t *testing.T) {
		h, barrier := testShamirBarrierContext(t)
		initializeShamirBarrier(t, barrier)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/initialize-shamir",
			strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		h.BarrierInitializeShamirHandler(w, req)

		assert.Equal(t, http.StatusConflict, w.Code)
	})
}

// --- BarrierUnsealShareHandler ---

func TestBarrierUnsealShareHandler(t *testing.T) {
	t.Run("submits share and returns progress", func(t *testing.T) {
		h, barrier := testShamirBarrierContext(t)
		shares := initializeShamirBarrier(t, barrier)
		require.NoError(t, barrier.Seal())

		body := `{"share":"` + shares[0] + `"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/unseal-share",
			strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		h.BarrierUnsealShareHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp seal.QuorumProgress
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, 2, resp.Required)
		assert.Equal(t, 1, resp.Submitted)
		assert.False(t, resp.Complete)
	})

	t.Run("unseals barrier when quorum is met", func(t *testing.T) {
		h, barrier := testShamirBarrierContext(t)
		shares := initializeShamirBarrier(t, barrier)
		require.NoError(t, barrier.Seal())

		// Submit first share
		body1 := `{"share":"` + shares[0] + `"}`
		req1 := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/unseal-share",
			strings.NewReader(body1))
		req1.Header.Set("Content-Type", "application/json")
		w1 := httptest.NewRecorder()
		h.BarrierUnsealShareHandler(w1, req1)
		assert.Equal(t, http.StatusOK, w1.Code)

		// Submit second share (meets threshold)
		body2 := `{"share":"` + shares[1] + `"}`
		req2 := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/unseal-share",
			strings.NewReader(body2))
		req2.Header.Set("Content-Type", "application/json")
		w2 := httptest.NewRecorder()
		h.BarrierUnsealShareHandler(w2, req2)
		assert.Equal(t, http.StatusOK, w2.Code)

		var resp seal.QuorumProgress
		err := json.NewDecoder(w2.Body).Decode(&resp)
		require.NoError(t, err)
		assert.True(t, resp.Complete)
		assert.False(t, barrier.IsSealed())
	})

	t.Run("returns 503 when barrier is nil", func(t *testing.T) {
		h := NewHandlerContext("test")

		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/unseal-share",
			strings.NewReader(`{"share":"abc"}`))
		w := httptest.NewRecorder()

		h.BarrierUnsealShareHandler(w, req)
		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("returns 400 for missing share", func(t *testing.T) {
		h, _ := testShamirBarrierContext(t)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/unseal-share",
			strings.NewReader(`{"share":""}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		h.BarrierUnsealShareHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 for invalid JSON", func(t *testing.T) {
		h, _ := testShamirBarrierContext(t)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/unseal-share",
			strings.NewReader(`{invalid`))
		w := httptest.NewRecorder()

		h.BarrierUnsealShareHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// --- BarrierUnsealSharesHandler ---

func TestBarrierUnsealSharesHandler(t *testing.T) {
	t.Run("unseals barrier with all shares at once", func(t *testing.T) {
		h, barrier := testShamirBarrierContext(t)
		shares := initializeShamirBarrier(t, barrier)
		require.NoError(t, barrier.Seal())

		body, err := json.Marshal(BarrierUnsealSharesRequest{Shares: shares[:2]})
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/unseal-shares",
			strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		h.BarrierUnsealSharesHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.False(t, barrier.IsSealed())

		var resp SuccessResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.True(t, resp.Success)
	})

	t.Run("returns 503 when barrier is nil", func(t *testing.T) {
		h := NewHandlerContext("test")

		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/unseal-shares",
			strings.NewReader(`{"shares":["a","b"]}`))
		w := httptest.NewRecorder()

		h.BarrierUnsealSharesHandler(w, req)
		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("returns 400 for missing shares", func(t *testing.T) {
		h, _ := testShamirBarrierContext(t)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/unseal-shares",
			strings.NewReader(`{"shares":[]}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		h.BarrierUnsealSharesHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 for invalid JSON", func(t *testing.T) {
		h, _ := testShamirBarrierContext(t)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/unseal-shares",
			strings.NewReader(`{invalid`))
		w := httptest.NewRecorder()

		h.BarrierUnsealSharesHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 422 for insufficient shares", func(t *testing.T) {
		h, barrier := testShamirBarrierContext(t)
		shares := initializeShamirBarrier(t, barrier)
		require.NoError(t, barrier.Seal())

		// Only provide 1 share when threshold is 2
		body, err := json.Marshal(BarrierUnsealSharesRequest{Shares: shares[:1]})
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/unseal-shares",
			strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		h.BarrierUnsealSharesHandler(w, req)
		assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	})
}

// --- BarrierRekeyHandler ---

func TestBarrierRekeyHandler(t *testing.T) {
	t.Run("rekeys barrier with new parameters", func(t *testing.T) {
		h, barrier := testShamirBarrierContext(t)
		initializeShamirBarrier(t, barrier)

		body := `{"threshold":2,"total":5}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/rekey",
			strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		h.BarrierRekeyHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp struct {
			Threshold   int `json:"threshold"`
			TotalShares int `json:"total_shares"`
			ShareCount  int `json:"share_count"`
		}
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, 5, resp.ShareCount)
		assert.Equal(t, 2, resp.Threshold)
		assert.Equal(t, 5, resp.TotalShares)
	})

	t.Run("returns 503 when barrier is nil", func(t *testing.T) {
		h := NewHandlerContext("test")

		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/rekey",
			strings.NewReader(`{"threshold":2,"total":3}`))
		w := httptest.NewRecorder()

		h.BarrierRekeyHandler(w, req)
		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("returns 400 for invalid JSON", func(t *testing.T) {
		h, _ := testShamirBarrierContext(t)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/rekey",
			strings.NewReader(`{invalid`))
		w := httptest.NewRecorder()

		h.BarrierRekeyHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 for threshold less than 2", func(t *testing.T) {
		h, _ := testShamirBarrierContext(t)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/rekey",
			strings.NewReader(`{"threshold":1,"total":3}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		h.BarrierRekeyHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 for total less than threshold", func(t *testing.T) {
		h, _ := testShamirBarrierContext(t)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/rekey",
			strings.NewReader(`{"threshold":3,"total":2}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		h.BarrierRekeyHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns conflict when barrier is sealed", func(t *testing.T) {
		h, barrier := testShamirBarrierContext(t)
		initializeShamirBarrier(t, barrier)
		require.NoError(t, barrier.Seal())

		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/rekey",
			strings.NewReader(`{"threshold":2,"total":5}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		h.BarrierRekeyHandler(w, req)
		assert.Equal(t, http.StatusConflict, w.Code)
	})
}

// --- BarrierGenerateRecoveryKeysHandler ---

func TestBarrierGenerateRecoveryKeysHandler(t *testing.T) {
	t.Run("generates recovery keys", func(t *testing.T) {
		h, barrier := testShamirBarrierContext(t)
		initializeShamirBarrier(t, barrier)

		// Wire a recovery distributor so GenerateRecoveryKeys can seal shares.
		recoveryDist := shamirtest.New(t)
		barrier.SetRecoveryDistributor(recoveryDist)

		body := `{"threshold":2,"total":3}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/recovery-keys/generate",
			strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		h.BarrierGenerateRecoveryKeysHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp seal.RecoveryKeyResult
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, 3, resp.ShareCount)
		assert.Equal(t, 2, resp.Threshold)
		assert.Equal(t, 3, resp.TotalShares)
	})

	t.Run("returns 503 when barrier is nil", func(t *testing.T) {
		h := NewHandlerContext("test")

		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/recovery-keys/generate",
			strings.NewReader(`{"threshold":2,"total":3}`))
		w := httptest.NewRecorder()

		h.BarrierGenerateRecoveryKeysHandler(w, req)
		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("returns 400 for invalid JSON", func(t *testing.T) {
		h, _ := testShamirBarrierContext(t)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/recovery-keys/generate",
			strings.NewReader(`{invalid`))
		w := httptest.NewRecorder()

		h.BarrierGenerateRecoveryKeysHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 for threshold less than 2", func(t *testing.T) {
		h, _ := testShamirBarrierContext(t)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/recovery-keys/generate",
			strings.NewReader(`{"threshold":1,"total":3}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		h.BarrierGenerateRecoveryKeysHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 for total less than threshold", func(t *testing.T) {
		h, _ := testShamirBarrierContext(t)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/recovery-keys/generate",
			strings.NewReader(`{"threshold":3,"total":2}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		h.BarrierGenerateRecoveryKeysHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// --- BarrierRecoverWithKeysHandler ---

func TestBarrierRecoverWithKeysHandler(t *testing.T) {
	t.Run("recovers barrier with recovery keys", func(t *testing.T) {
		h, barrier := testShamirBarrierContext(t)
		initializeShamirBarrier(t, barrier)

		// Wire a fresh recovery distributor for recovery key generation.
		recoveryDist := shamirtest.New(t)
		barrier.SetRecoveryDistributor(recoveryDist)

		// Generate recovery keys while unsealed
		_, err := barrier.GenerateRecoveryKeys(context.Background(), 2, 3)
		require.NoError(t, err)
		recoveryShares := recoveryDist.Shares()
		require.GreaterOrEqual(t, len(recoveryShares), 2)

		// Seal the barrier
		require.NoError(t, barrier.Seal())
		assert.True(t, barrier.IsSealed())

		body, err := json.Marshal(BarrierRecoverWithKeysRequest{Keys: recoveryShares[:2]})
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/recovery-keys/recover",
			strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		h.BarrierRecoverWithKeysHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.False(t, barrier.IsSealed())
	})

	t.Run("returns 503 when barrier is nil", func(t *testing.T) {
		h := NewHandlerContext("test")

		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/recovery-keys/recover",
			strings.NewReader(`{"keys":["a","b"]}`))
		w := httptest.NewRecorder()

		h.BarrierRecoverWithKeysHandler(w, req)
		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("returns 400 for missing keys", func(t *testing.T) {
		h, _ := testShamirBarrierContext(t)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/recovery-keys/recover",
			strings.NewReader(`{"keys":[]}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		h.BarrierRecoverWithKeysHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 for invalid JSON", func(t *testing.T) {
		h, _ := testShamirBarrierContext(t)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/recovery-keys/recover",
			strings.NewReader(`{invalid`))
		w := httptest.NewRecorder()

		h.BarrierRecoverWithKeysHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// --- BarrierDeleteRecoveryKeysHandler ---

func TestBarrierDeleteRecoveryKeysHandler(t *testing.T) {
	t.Run("deletes recovery key metadata", func(t *testing.T) {
		h, barrier := testShamirBarrierContext(t)
		initializeShamirBarrier(t, barrier)

		// Wire a recovery distributor so GenerateRecoveryKeys can seal shares.
		barrier.SetRecoveryDistributor(shamirtest.New(t))

		// Generate recovery keys first
		_, err := barrier.GenerateRecoveryKeys(context.Background(), 2, 3)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/barrier/recovery-keys", nil)
		w := httptest.NewRecorder()

		h.BarrierDeleteRecoveryKeysHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp SuccessResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.True(t, resp.Success)
	})

	t.Run("returns 503 when barrier is nil", func(t *testing.T) {
		h := NewHandlerContext("test")

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/barrier/recovery-keys", nil)
		w := httptest.NewRecorder()

		h.BarrierDeleteRecoveryKeysHandler(w, req)
		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("returns conflict when barrier is sealed", func(t *testing.T) {
		h, barrier := testShamirBarrierContext(t)
		initializeShamirBarrier(t, barrier)
		require.NoError(t, barrier.Seal())

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/barrier/recovery-keys", nil)
		w := httptest.NewRecorder()

		h.BarrierDeleteRecoveryKeysHandler(w, req)
		assert.Equal(t, http.StatusConflict, w.Code)
	})
}

// --- BarrierGenerateRootTokenHandler ---

func TestBarrierGenerateRootTokenHandler(t *testing.T) {
	t.Run("generates root token with valid shares", func(t *testing.T) {
		h, barrier := testShamirBarrierContext(t)
		shares := initializeShamirBarrier(t, barrier)

		body, err := json.Marshal(BarrierGenerateRootTokenRequest{Shares: shares[:2]})
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/root-token",
			strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		h.BarrierGenerateRootTokenHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp seal.RootToken
		err = json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.NotEmpty(t, resp.Token)
		assert.False(t, resp.CreatedAt.IsZero())
	})

	t.Run("returns 503 when barrier is nil", func(t *testing.T) {
		h := NewHandlerContext("test")

		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/root-token",
			strings.NewReader(`{"shares":["a","b"]}`))
		w := httptest.NewRecorder()

		h.BarrierGenerateRootTokenHandler(w, req)
		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("returns 400 for missing shares", func(t *testing.T) {
		h, _ := testShamirBarrierContext(t)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/root-token",
			strings.NewReader(`{"shares":[]}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		h.BarrierGenerateRootTokenHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 for invalid JSON", func(t *testing.T) {
		h, _ := testShamirBarrierContext(t)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/root-token",
			strings.NewReader(`{invalid`))
		w := httptest.NewRecorder()

		h.BarrierGenerateRootTokenHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 422 for insufficient shares", func(t *testing.T) {
		h, barrier := testShamirBarrierContext(t)
		shares := initializeShamirBarrier(t, barrier)

		// Only provide 1 share when threshold is 2
		body, err := json.Marshal(BarrierGenerateRootTokenRequest{Shares: shares[:1]})
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/root-token",
			strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		h.BarrierGenerateRootTokenHandler(w, req)
		assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	})
}

// --- handleBarrierError Shamir error mapping ---

func TestHandleBarrierErrorShamirMappings(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{"ShamirNotConfigured", seal.ErrShamirNotConfigured, http.StatusBadRequest},
		{"ShamirThresholdInvalid", seal.ErrShamirThresholdInvalid, http.StatusBadRequest},
		{"ShamirQuorumIncomplete", seal.ErrShamirQuorumIncomplete, http.StatusUnprocessableEntity},
		{"ShamirQuorumExpired", seal.ErrShamirQuorumExpired, http.StatusGone},
		{"ShamirDuplicateShare", seal.ErrShamirDuplicateShare, http.StatusConflict},
		{"ShamirCombineFailed", seal.ErrShamirCombineFailed, http.StatusInternalServerError},
		{"ShamirShareNotFound", seal.ErrShamirShareNotFound, http.StatusNotFound},
		{"ShamirNoSharesFound", seal.ErrShamirNoSharesFound, http.StatusNotFound},
		{"ShamirVerificationFailed", seal.ErrShamirVerificationFailed, http.StatusInternalServerError},
		{"ShamirStorageFailed", seal.ErrShamirStorageFailed, http.StatusInternalServerError},
		{"RecoveryKeysNotFound", seal.ErrRecoveryKeysNotFound, http.StatusNotFound},
		{"RootTokenVerificationFailed", seal.ErrRootTokenVerificationFailed, http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			handleBarrierError(w, tt.err)
			assert.Equal(t, tt.wantStatus, w.Code)
		})
	}
}
