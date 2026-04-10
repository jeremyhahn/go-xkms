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

	"github.com/go-chi/chi/v5"
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
	shamirStrat, err := seal.NewShamirStrategy(store, 2, 3)
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

	h := NewHandlerContext("test")
	h.SetBarrier(barrier)
	return h, barrier
}

// initializeShamirBarrier is a test helper that initializes the Shamir barrier
// and returns the generated shares.
func initializeShamirBarrier(t *testing.T, barrier *seal.Barrier) []string {
	t.Helper()

	result, err := barrier.InitializeShamir(context.Background(), seal.Credentials{})
	require.NoError(t, err)
	require.Len(t, result.Shares, 3)
	return result.Shares
}

// --- BarrierInitializeShamirHandler ---

func TestBarrierInitializeShamirHandler(t *testing.T) {
	t.Run("initializes barrier with shamir shares", func(t *testing.T) {
		h, _ := testShamirBarrierContext(t)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/initialize-shamir",
			strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		h.BarrierInitializeShamirHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp seal.ShamirInitResult
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, 3, len(resp.Shares))
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

// --- BarrierShamirListSharesHandler ---

func TestBarrierShamirListSharesHandler(t *testing.T) {
	t.Run("lists shares with count and configuration", func(t *testing.T) {
		h, barrier := testShamirBarrierContext(t)
		initializeShamirBarrier(t, barrier)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/barrier/shamir/shares", nil)
		w := httptest.NewRecorder()

		h.BarrierShamirListSharesHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp BarrierShamirSharesResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, 3, resp.Count)
		assert.Equal(t, 2, resp.Threshold)
		assert.Equal(t, 3, resp.Total)
	})

	t.Run("returns 503 when barrier is nil", func(t *testing.T) {
		h := NewHandlerContext("test")

		req := httptest.NewRequest(http.MethodGet, "/api/v1/barrier/shamir/shares", nil)
		w := httptest.NewRecorder()

		h.BarrierShamirListSharesHandler(w, req)
		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("returns 400 when shamir not configured", func(t *testing.T) {
		store := storage.NewMemory()
		softStrat := seal.NewSoftwareStrategy()
		barrier, err := seal.NewBarrier(slog.Default(), store, seal.BarrierConfig{
			RootKeyPath: "test-root-key",
		}, softStrat)
		require.NoError(t, err)

		h := NewHandlerContext("test")
		h.SetBarrier(barrier)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/barrier/shamir/shares", nil)
		w := httptest.NewRecorder()

		h.BarrierShamirListSharesHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// --- BarrierShamirDeleteShareHandler ---

func TestBarrierShamirDeleteShareHandler(t *testing.T) {
	t.Run("deletes a share by index", func(t *testing.T) {
		h, barrier := testShamirBarrierContext(t)
		initializeShamirBarrier(t, barrier)

		// Set up chi route context for URL parameter
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("index", "1")
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/barrier/shamir/shares/1", nil)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		w := httptest.NewRecorder()

		h.BarrierShamirDeleteShareHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp SuccessResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.True(t, resp.Success)

		// Verify share count decreased
		count, err := barrier.ShamirStrategy().ShareCount(context.Background())
		require.NoError(t, err)
		assert.Equal(t, 2, count)
	})

	t.Run("returns 503 when barrier is nil", func(t *testing.T) {
		h := NewHandlerContext("test")

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("index", "1")
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/barrier/shamir/shares/1", nil)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		w := httptest.NewRecorder()

		h.BarrierShamirDeleteShareHandler(w, req)
		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("returns 400 for invalid index", func(t *testing.T) {
		h, barrier := testShamirBarrierContext(t)
		initializeShamirBarrier(t, barrier)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("index", "abc")
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/barrier/shamir/shares/abc", nil)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		w := httptest.NewRecorder()

		h.BarrierShamirDeleteShareHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 400 for zero index", func(t *testing.T) {
		h, barrier := testShamirBarrierContext(t)
		initializeShamirBarrier(t, barrier)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("index", "0")
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/barrier/shamir/shares/0", nil)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		w := httptest.NewRecorder()

		h.BarrierShamirDeleteShareHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 404 for non-existent share", func(t *testing.T) {
		h, barrier := testShamirBarrierContext(t)
		initializeShamirBarrier(t, barrier)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("index", "99")
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/barrier/shamir/shares/99", nil)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		w := httptest.NewRecorder()

		h.BarrierShamirDeleteShareHandler(w, req)
		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// --- BarrierShamirDeleteAllSharesHandler ---

func TestBarrierShamirDeleteAllSharesHandler(t *testing.T) {
	t.Run("deletes all shares", func(t *testing.T) {
		h, barrier := testShamirBarrierContext(t)
		initializeShamirBarrier(t, barrier)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/barrier/shamir/shares", nil)
		w := httptest.NewRecorder()

		h.BarrierShamirDeleteAllSharesHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp SuccessResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.True(t, resp.Success)

		// Verify all shares deleted
		count, err := barrier.ShamirStrategy().ShareCount(context.Background())
		require.NoError(t, err)
		assert.Equal(t, 0, count)
	})

	t.Run("returns 503 when barrier is nil", func(t *testing.T) {
		h := NewHandlerContext("test")

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/barrier/shamir/shares", nil)
		w := httptest.NewRecorder()

		h.BarrierShamirDeleteAllSharesHandler(w, req)
		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

// --- BarrierShamirVerifyHandler ---

func TestBarrierShamirVerifyHandler(t *testing.T) {
	t.Run("verifies shares successfully", func(t *testing.T) {
		h, barrier := testShamirBarrierContext(t)
		initializeShamirBarrier(t, barrier)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/shamir/verify", nil)
		w := httptest.NewRecorder()

		h.BarrierShamirVerifyHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp SuccessResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.True(t, resp.Success)
		assert.Equal(t, "shares verified", resp.Message)
	})

	t.Run("returns 503 when barrier is nil", func(t *testing.T) {
		h := NewHandlerContext("test")

		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/shamir/verify", nil)
		w := httptest.NewRecorder()

		h.BarrierShamirVerifyHandler(w, req)
		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("returns error when no shares exist", func(t *testing.T) {
		h, barrier := testShamirBarrierContext(t)
		initializeShamirBarrier(t, barrier)

		// Delete all shares first
		err := barrier.ShamirStrategy().DeleteAllShares(context.Background())
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/shamir/verify", nil)
		w := httptest.NewRecorder()

		h.BarrierShamirVerifyHandler(w, req)
		assert.Equal(t, http.StatusNotFound, w.Code)
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

		var resp seal.ShamirInitResult
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, 5, len(resp.Shares))
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
		assert.Equal(t, 3, len(resp.Shares))
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

		// Generate recovery keys while unsealed
		result, err := barrier.GenerateRecoveryKeys(context.Background(), 2, 3)
		require.NoError(t, err)

		// Seal the barrier
		require.NoError(t, barrier.Seal())
		assert.True(t, barrier.IsSealed())

		body, err := json.Marshal(BarrierRecoverWithKeysRequest{Keys: result.Shares[:2]})
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
