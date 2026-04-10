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

package quic

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestServerWithShamirBarrier creates a QUIC test server with a
// StrategyShamir-backed barrier in direct mode. The barrier is initialized
// and ready for Shamir operations. Returns the server, the shares from
// initialization, and the barrier for direct access in tests.
func createTestServerWithShamirBarrier(t *testing.T) (*Server, []string, *seal.Barrier) {
	t.Helper()

	xkms.Reset()

	mockKS := xkmsmocks.NewMockKeyStore()
	err := xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"software": mockKS},
		DefaultBackend: "software",
	})
	require.NoError(t, err)

	barrierStore := storage.NewMemory()
	shareStore := storage.NewMemory()

	shamirStrat, err := seal.NewShamirStrategy(shareStore, 2, 3)
	require.NoError(t, err)

	barrier, err := seal.NewBarrier(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		barrierStore,
		seal.BarrierConfig{
			RootKeyPath:     "core/seal",
			PreferenceOrder: []seal.StrategyID{seal.StrategyShamir},
			Shamir:          &seal.ShamirConfig{Threshold: 2, TotalShares: 3},
		},
		shamirStrat,
	)
	require.NoError(t, err)

	// Initialize the barrier to get shares.
	result, err := barrier.InitializeShamir(context.Background(), seal.Credentials{})
	require.NoError(t, err)
	require.Len(t, result.Shares, 3)

	cfg := &Config{
		Addr:          "localhost:8444",
		Authenticator: auth.NewNoOpAuthenticator(),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		Barrier:       barrier,
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)

	return server, result.Shares, barrier
}

// createTestServerWithSealedShamirBarrier creates a QUIC test server with
// a StrategyShamir-backed barrier that has been initialized and then sealed.
func createTestServerWithSealedShamirBarrier(t *testing.T) (*Server, []string, *seal.Barrier) {
	t.Helper()

	server, shares, barrier := createTestServerWithShamirBarrier(t)

	// Seal the barrier so it's ready for unseal tests.
	err := barrier.Seal()
	require.NoError(t, err)

	return server, shares, barrier
}

// createTestServerNoBarrier creates a QUIC test server with no barrier configured.
func createTestServerNoBarrier(t *testing.T) *Server {
	t.Helper()

	xkms.Reset()

	mockKS := xkmsmocks.NewMockKeyStore()
	err := xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"software": mockKS},
		DefaultBackend: "software",
	})
	require.NoError(t, err)

	cfg := &Config{
		Addr:          "localhost:8444",
		Authenticator: auth.NewNoOpAuthenticator(),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)
	return server
}

// createTestServerWithCredentialShamirBarrier creates a barrier using software
// strategy (credential mode) with Shamir config but no StrategyShamir registered.
func createTestServerWithCredentialShamirBarrier(t *testing.T) (*Server, *seal.Barrier) {
	t.Helper()

	xkms.Reset()

	mockKS := xkmsmocks.NewMockKeyStore()
	err := xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"software": mockKS},
		DefaultBackend: "software",
	})
	require.NoError(t, err)

	barrierStore := storage.NewMemory()

	barrier, err := seal.NewBarrier(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		barrierStore,
		seal.BarrierConfig{
			RootKeyPath:     "core/seal",
			PreferenceOrder: []seal.StrategyID{seal.StrategySoftware},
			Shamir:          &seal.ShamirConfig{Threshold: 2, TotalShares: 3},
		},
		seal.NewSoftwareStrategy(),
	)
	require.NoError(t, err)

	cfg := &Config{
		Addr:          "localhost:8444",
		Authenticator: auth.NewNoOpAuthenticator(),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		Barrier:       barrier,
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)
	return server, barrier
}

// --- Initialize Shamir tests ---

func TestBarrierShamirInitialize(t *testing.T) {
	t.Run("POST initializes Shamir barrier with credential mode", func(t *testing.T) {
		server, barrier := createTestServerWithCredentialShamirBarrier(t)
		defer xkms.Reset()
		_ = barrier

		body, err := json.Marshal(BarrierInitializeShamirRequest{Secret: "test-secret"})
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/initialize-shamir", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp map[string]interface{}
		err = json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, true, resp["success"])
		assert.NotNil(t, resp["shares"])
		assert.Equal(t, float64(2), resp["threshold"])
		assert.Equal(t, float64(3), resp["total_shares"])

		shares, ok := resp["shares"].([]interface{})
		require.True(t, ok)
		assert.Len(t, shares, 3)
	})

	t.Run("GET method not allowed", func(t *testing.T) {
		server, _ := createTestServerWithCredentialShamirBarrier(t)
		defer xkms.Reset()

		req := httptest.NewRequest(http.MethodGet, "/api/v1/barrier/initialize-shamir", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("barrier not configured returns service unavailable", func(t *testing.T) {
		server := createTestServerNoBarrier(t)
		defer xkms.Reset()

		body, err := json.Marshal(BarrierInitializeShamirRequest{Secret: "test"})
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/initialize-shamir", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("invalid JSON returns bad request", func(t *testing.T) {
		server, _ := createTestServerWithCredentialShamirBarrier(t)
		defer xkms.Reset()

		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/initialize-shamir", strings.NewReader("{bad json"))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("already initialized returns conflict", func(t *testing.T) {
		server, _, _ := createTestServerWithShamirBarrier(t)
		defer xkms.Reset()

		body, err := json.Marshal(BarrierInitializeShamirRequest{})
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/initialize-shamir", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusConflict, w.Code)
	})
}

// --- Unseal Share tests ---

func TestBarrierShamirUnsealShare(t *testing.T) {
	t.Run("POST submits share and tracks quorum progress", func(t *testing.T) {
		server, shares, _ := createTestServerWithSealedShamirBarrier(t)
		defer xkms.Reset()

		// Submit first share
		body, err := json.Marshal(BarrierUnsealShareRequest{Share: shares[0]})
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/unseal-share", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp map[string]interface{}
		err = json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, true, resp["success"])
		assert.Equal(t, float64(2), resp["required"])
		assert.Equal(t, float64(1), resp["submitted"])
		assert.Equal(t, false, resp["complete"])
	})

	t.Run("POST submits enough shares to unseal", func(t *testing.T) {
		server, shares, _ := createTestServerWithSealedShamirBarrier(t)
		defer xkms.Reset()

		// Submit first share
		body1, _ := json.Marshal(BarrierUnsealShareRequest{Share: shares[0]})
		req1 := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/unseal-share", bytes.NewReader(body1))
		w1 := httptest.NewRecorder()
		server.handler.ServeHTTP(w1, req1)
		assert.Equal(t, http.StatusOK, w1.Code)

		// Submit second share (should complete quorum)
		body2, _ := json.Marshal(BarrierUnsealShareRequest{Share: shares[1]})
		req2 := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/unseal-share", bytes.NewReader(body2))
		w2 := httptest.NewRecorder()
		server.handler.ServeHTTP(w2, req2)
		assert.Equal(t, http.StatusOK, w2.Code)

		var resp map[string]interface{}
		err := json.NewDecoder(w2.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, true, resp["success"])
		assert.Equal(t, true, resp["complete"])
	})

	t.Run("empty share returns bad request", func(t *testing.T) {
		server, _, _ := createTestServerWithSealedShamirBarrier(t)
		defer xkms.Reset()

		body, _ := json.Marshal(BarrierUnsealShareRequest{Share: ""})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/unseal-share", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("GET method not allowed", func(t *testing.T) {
		server, _, _ := createTestServerWithSealedShamirBarrier(t)
		defer xkms.Reset()

		req := httptest.NewRequest(http.MethodGet, "/api/v1/barrier/unseal-share", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("barrier not configured returns service unavailable", func(t *testing.T) {
		server := createTestServerNoBarrier(t)
		defer xkms.Reset()

		body, _ := json.Marshal(BarrierUnsealShareRequest{Share: "share"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/unseal-share", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("duplicate share returns conflict", func(t *testing.T) {
		server, shares, _ := createTestServerWithSealedShamirBarrier(t)
		defer xkms.Reset()

		body, _ := json.Marshal(BarrierUnsealShareRequest{Share: shares[0]})

		// First submission
		req1 := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/unseal-share", bytes.NewReader(body))
		w1 := httptest.NewRecorder()
		server.handler.ServeHTTP(w1, req1)
		assert.Equal(t, http.StatusOK, w1.Code)

		// Duplicate
		req2 := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/unseal-share", bytes.NewReader(body))
		w2 := httptest.NewRecorder()
		server.handler.ServeHTTP(w2, req2)
		assert.Equal(t, http.StatusConflict, w2.Code)
	})

	t.Run("invalid JSON returns bad request", func(t *testing.T) {
		server, _, _ := createTestServerWithSealedShamirBarrier(t)
		defer xkms.Reset()

		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/unseal-share", strings.NewReader("{bad"))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// --- Unseal Shares (batch) tests ---

func TestBarrierShamirUnsealShares(t *testing.T) {
	t.Run("POST unseals with all shares at once", func(t *testing.T) {
		server, shares, _ := createTestServerWithSealedShamirBarrier(t)
		defer xkms.Reset()

		body, _ := json.Marshal(BarrierUnsealSharesRequest{Shares: shares[:2]})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/unseal-shares", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp map[string]interface{}
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, true, resp["success"])
	})

	t.Run("empty shares returns bad request", func(t *testing.T) {
		server, _, _ := createTestServerWithSealedShamirBarrier(t)
		defer xkms.Reset()

		body, _ := json.Marshal(BarrierUnsealSharesRequest{Shares: []string{}})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/unseal-shares", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("insufficient shares returns unprocessable entity", func(t *testing.T) {
		server, shares, _ := createTestServerWithSealedShamirBarrier(t)
		defer xkms.Reset()

		// Only 1 share, need 2
		body, _ := json.Marshal(BarrierUnsealSharesRequest{Shares: shares[:1]})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/unseal-shares", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	})

	t.Run("GET method not allowed", func(t *testing.T) {
		server, _, _ := createTestServerWithSealedShamirBarrier(t)
		defer xkms.Reset()

		req := httptest.NewRequest(http.MethodGet, "/api/v1/barrier/unseal-shares", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("barrier not configured returns service unavailable", func(t *testing.T) {
		server := createTestServerNoBarrier(t)
		defer xkms.Reset()

		body, _ := json.Marshal(BarrierUnsealSharesRequest{Shares: []string{"a", "b"}})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/unseal-shares", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("invalid JSON returns bad request", func(t *testing.T) {
		server, _, _ := createTestServerWithSealedShamirBarrier(t)
		defer xkms.Reset()

		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/unseal-shares", strings.NewReader("{bad"))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// --- Rekey tests ---

func TestBarrierShamirRekey(t *testing.T) {
	t.Run("POST rekeys with new parameters", func(t *testing.T) {
		server, _, _ := createTestServerWithShamirBarrier(t)
		defer xkms.Reset()

		body, _ := json.Marshal(BarrierRekeyRequest{Threshold: 3, Total: 5})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/rekey", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp map[string]interface{}
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, true, resp["success"])
		assert.Equal(t, float64(3), resp["threshold"])
		assert.Equal(t, float64(5), resp["total_shares"])

		shares, ok := resp["shares"].([]interface{})
		require.True(t, ok)
		assert.Len(t, shares, 5)
	})

	t.Run("threshold less than 2 returns bad request", func(t *testing.T) {
		server, _, _ := createTestServerWithShamirBarrier(t)
		defer xkms.Reset()

		body, _ := json.Marshal(BarrierRekeyRequest{Threshold: 1, Total: 3})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/rekey", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("total less than threshold returns bad request", func(t *testing.T) {
		server, _, _ := createTestServerWithShamirBarrier(t)
		defer xkms.Reset()

		body, _ := json.Marshal(BarrierRekeyRequest{Threshold: 3, Total: 2})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/rekey", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("GET method not allowed", func(t *testing.T) {
		server, _, _ := createTestServerWithShamirBarrier(t)
		defer xkms.Reset()

		req := httptest.NewRequest(http.MethodGet, "/api/v1/barrier/rekey", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("barrier not configured returns service unavailable", func(t *testing.T) {
		server := createTestServerNoBarrier(t)
		defer xkms.Reset()

		body, _ := json.Marshal(BarrierRekeyRequest{Threshold: 2, Total: 3})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/rekey", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("invalid JSON returns bad request", func(t *testing.T) {
		server, _, _ := createTestServerWithShamirBarrier(t)
		defer xkms.Reset()

		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/rekey", strings.NewReader("{bad"))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("rekey on sealed barrier returns conflict", func(t *testing.T) {
		server, _, barrier := createTestServerWithShamirBarrier(t)
		defer xkms.Reset()

		err := barrier.Seal()
		require.NoError(t, err)

		body, _ := json.Marshal(BarrierRekeyRequest{Threshold: 2, Total: 3})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/rekey", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusConflict, w.Code)
	})
}

// --- Root Token tests ---

func TestBarrierShamirGenerateRootToken(t *testing.T) {
	t.Run("POST generates root token with valid shares", func(t *testing.T) {
		server, shares, _ := createTestServerWithShamirBarrier(t)
		defer xkms.Reset()

		body, _ := json.Marshal(BarrierGenerateRootTokenRequest{Shares: shares[:2]})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/root-token", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp map[string]interface{}
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, true, resp["success"])
		assert.NotEmpty(t, resp["token"])
		assert.NotNil(t, resp["created_at"])
	})

	t.Run("empty shares returns bad request", func(t *testing.T) {
		server, _, _ := createTestServerWithShamirBarrier(t)
		defer xkms.Reset()

		body, _ := json.Marshal(BarrierGenerateRootTokenRequest{Shares: []string{}})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/root-token", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("insufficient shares returns unprocessable entity", func(t *testing.T) {
		server, shares, _ := createTestServerWithShamirBarrier(t)
		defer xkms.Reset()

		// Only 1 share, need 2
		body, _ := json.Marshal(BarrierGenerateRootTokenRequest{Shares: shares[:1]})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/root-token", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	})

	t.Run("GET method not allowed", func(t *testing.T) {
		server, _, _ := createTestServerWithShamirBarrier(t)
		defer xkms.Reset()

		req := httptest.NewRequest(http.MethodGet, "/api/v1/barrier/root-token", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("barrier not configured returns service unavailable", func(t *testing.T) {
		server := createTestServerNoBarrier(t)
		defer xkms.Reset()

		body, _ := json.Marshal(BarrierGenerateRootTokenRequest{Shares: []string{"a", "b"}})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/root-token", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("invalid JSON returns bad request", func(t *testing.T) {
		server, _, _ := createTestServerWithShamirBarrier(t)
		defer xkms.Reset()

		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/root-token", strings.NewReader("{bad"))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// --- Shamir Shares (list/delete all) tests ---

func TestBarrierShamirShares(t *testing.T) {
	t.Run("GET lists share count and configuration", func(t *testing.T) {
		server, _, _ := createTestServerWithShamirBarrier(t)
		defer xkms.Reset()

		req := httptest.NewRequest(http.MethodGet, "/api/v1/barrier/shamir/shares", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp BarrierShamirSharesResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, 3, resp.Count)
		assert.Equal(t, 2, resp.Threshold)
		assert.Equal(t, 3, resp.Total)
	})

	t.Run("DELETE removes all shares", func(t *testing.T) {
		server, _, _ := createTestServerWithShamirBarrier(t)
		defer xkms.Reset()

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/barrier/shamir/shares", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp map[string]interface{}
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, true, resp["success"])

		// Verify shares are gone by listing
		req2 := httptest.NewRequest(http.MethodGet, "/api/v1/barrier/shamir/shares", nil)
		w2 := httptest.NewRecorder()
		server.handler.ServeHTTP(w2, req2)

		assert.Equal(t, http.StatusOK, w2.Code)

		var resp2 BarrierShamirSharesResponse
		err = json.NewDecoder(w2.Body).Decode(&resp2)
		require.NoError(t, err)
		assert.Equal(t, 0, resp2.Count)
	})

	t.Run("POST method not allowed", func(t *testing.T) {
		server, _, _ := createTestServerWithShamirBarrier(t)
		defer xkms.Reset()

		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/shamir/shares", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("barrier not configured returns service unavailable", func(t *testing.T) {
		server := createTestServerNoBarrier(t)
		defer xkms.Reset()

		req := httptest.NewRequest(http.MethodGet, "/api/v1/barrier/shamir/shares", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("no Shamir strategy returns bad request", func(t *testing.T) {
		server, _ := createTestServerWithCredentialShamirBarrier(t)
		defer xkms.Reset()

		req := httptest.NewRequest(http.MethodGet, "/api/v1/barrier/shamir/shares", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		// Credential mode barrier has no ShamirStrategy registered
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// --- Shamir Delete Specific Share tests ---

func TestBarrierShamirDeleteShare(t *testing.T) {
	t.Run("DELETE removes specific share by index", func(t *testing.T) {
		server, _, _ := createTestServerWithShamirBarrier(t)
		defer xkms.Reset()

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/barrier/shamir/shares/1", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp map[string]interface{}
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, true, resp["success"])
		assert.Equal(t, float64(1), resp["index"])
	})

	t.Run("invalid index returns bad request", func(t *testing.T) {
		server, _, _ := createTestServerWithShamirBarrier(t)
		defer xkms.Reset()

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/barrier/shamir/shares/abc", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("GET method not allowed", func(t *testing.T) {
		server, _, _ := createTestServerWithShamirBarrier(t)
		defer xkms.Reset()

		req := httptest.NewRequest(http.MethodGet, "/api/v1/barrier/shamir/shares/1", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("barrier not configured returns service unavailable", func(t *testing.T) {
		server := createTestServerNoBarrier(t)
		defer xkms.Reset()

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/barrier/shamir/shares/1", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("no Shamir strategy returns bad request", func(t *testing.T) {
		server, _ := createTestServerWithCredentialShamirBarrier(t)
		defer xkms.Reset()

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/barrier/shamir/shares/1", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("nonexistent share index returns not found", func(t *testing.T) {
		server, _, _ := createTestServerWithShamirBarrier(t)
		defer xkms.Reset()

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/barrier/shamir/shares/999", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// --- Shamir Verify tests ---

func TestBarrierShamirVerify(t *testing.T) {
	t.Run("POST verifies shares successfully", func(t *testing.T) {
		server, _, _ := createTestServerWithShamirBarrier(t)
		defer xkms.Reset()

		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/shamir/verify", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp map[string]interface{}
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, true, resp["success"])
	})

	t.Run("GET method not allowed", func(t *testing.T) {
		server, _, _ := createTestServerWithShamirBarrier(t)
		defer xkms.Reset()

		req := httptest.NewRequest(http.MethodGet, "/api/v1/barrier/shamir/verify", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("barrier not configured returns service unavailable", func(t *testing.T) {
		server := createTestServerNoBarrier(t)
		defer xkms.Reset()

		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/shamir/verify", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("no Shamir strategy returns bad request", func(t *testing.T) {
		server, _ := createTestServerWithCredentialShamirBarrier(t)
		defer xkms.Reset()

		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/shamir/verify", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// --- Recovery Keys Generate tests ---

func TestBarrierShamirGenerateRecoveryKeys(t *testing.T) {
	t.Run("POST generates recovery keys", func(t *testing.T) {
		server, _, _ := createTestServerWithShamirBarrier(t)
		defer xkms.Reset()

		body, _ := json.Marshal(BarrierGenerateRecoveryKeysRequest{Threshold: 2, Total: 3})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/recovery-keys/generate", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp map[string]interface{}
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, true, resp["success"])
		assert.Equal(t, float64(2), resp["threshold"])
		assert.Equal(t, float64(3), resp["total_shares"])

		shares, ok := resp["shares"].([]interface{})
		require.True(t, ok)
		assert.Len(t, shares, 3)
	})

	t.Run("threshold less than 2 returns bad request", func(t *testing.T) {
		server, _, _ := createTestServerWithShamirBarrier(t)
		defer xkms.Reset()

		body, _ := json.Marshal(BarrierGenerateRecoveryKeysRequest{Threshold: 1, Total: 3})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/recovery-keys/generate", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("total less than threshold returns bad request", func(t *testing.T) {
		server, _, _ := createTestServerWithShamirBarrier(t)
		defer xkms.Reset()

		body, _ := json.Marshal(BarrierGenerateRecoveryKeysRequest{Threshold: 3, Total: 2})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/recovery-keys/generate", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("GET method not allowed", func(t *testing.T) {
		server, _, _ := createTestServerWithShamirBarrier(t)
		defer xkms.Reset()

		req := httptest.NewRequest(http.MethodGet, "/api/v1/barrier/recovery-keys/generate", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("barrier not configured returns service unavailable", func(t *testing.T) {
		server := createTestServerNoBarrier(t)
		defer xkms.Reset()

		body, _ := json.Marshal(BarrierGenerateRecoveryKeysRequest{Threshold: 2, Total: 3})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/recovery-keys/generate", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("invalid JSON returns bad request", func(t *testing.T) {
		server, _, _ := createTestServerWithShamirBarrier(t)
		defer xkms.Reset()

		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/recovery-keys/generate", strings.NewReader("{bad"))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("sealed barrier returns conflict", func(t *testing.T) {
		server, _, barrier := createTestServerWithShamirBarrier(t)
		defer xkms.Reset()

		err := barrier.Seal()
		require.NoError(t, err)

		body, _ := json.Marshal(BarrierGenerateRecoveryKeysRequest{Threshold: 2, Total: 3})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/recovery-keys/generate", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		// GetMasterKey fails when sealed
		assert.Contains(t, []int{http.StatusConflict, http.StatusInternalServerError}, w.Code)
	})
}

// --- Recover With Keys tests ---

func TestBarrierShamirRecoverWithKeys(t *testing.T) {
	t.Run("POST recovers barrier with recovery keys", func(t *testing.T) {
		server, _, barrier := createTestServerWithShamirBarrier(t)
		defer xkms.Reset()

		// Generate recovery keys while unsealed
		body, _ := json.Marshal(BarrierGenerateRecoveryKeysRequest{Threshold: 2, Total: 3})
		genReq := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/recovery-keys/generate", bytes.NewReader(body))
		genW := httptest.NewRecorder()
		server.handler.ServeHTTP(genW, genReq)
		require.Equal(t, http.StatusOK, genW.Code)

		var genResp map[string]interface{}
		err := json.NewDecoder(genW.Body).Decode(&genResp)
		require.NoError(t, err)
		sharesRaw := genResp["shares"].([]interface{})
		recoveryKeys := make([]string, len(sharesRaw))
		for i, s := range sharesRaw {
			recoveryKeys[i] = s.(string)
		}

		// Seal the barrier
		err = barrier.Seal()
		require.NoError(t, err)

		// Recover with keys
		recoverBody, _ := json.Marshal(BarrierRecoverWithKeysRequest{Keys: recoveryKeys[:2]})
		recoverReq := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/recovery-keys/recover", bytes.NewReader(recoverBody))
		recoverW := httptest.NewRecorder()
		server.handler.ServeHTTP(recoverW, recoverReq)

		assert.Equal(t, http.StatusOK, recoverW.Code)

		var resp map[string]interface{}
		err = json.NewDecoder(recoverW.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, true, resp["success"])
	})

	t.Run("empty keys returns bad request", func(t *testing.T) {
		server, _, _ := createTestServerWithSealedShamirBarrier(t)
		defer xkms.Reset()

		body, _ := json.Marshal(BarrierRecoverWithKeysRequest{Keys: []string{}})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/recovery-keys/recover", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("GET method not allowed", func(t *testing.T) {
		server, _, _ := createTestServerWithSealedShamirBarrier(t)
		defer xkms.Reset()

		req := httptest.NewRequest(http.MethodGet, "/api/v1/barrier/recovery-keys/recover", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("barrier not configured returns service unavailable", func(t *testing.T) {
		server := createTestServerNoBarrier(t)
		defer xkms.Reset()

		body, _ := json.Marshal(BarrierRecoverWithKeysRequest{Keys: []string{"a", "b"}})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/recovery-keys/recover", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("invalid JSON returns bad request", func(t *testing.T) {
		server, _, _ := createTestServerWithSealedShamirBarrier(t)
		defer xkms.Reset()

		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/recovery-keys/recover", strings.NewReader("{bad"))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// --- Recovery Keys Delete / Has tests ---

func TestBarrierShamirRecoveryKeys(t *testing.T) {
	t.Run("GET has_recovery_keys returns false when none exist", func(t *testing.T) {
		server, _, _ := createTestServerWithShamirBarrier(t)
		defer xkms.Reset()

		req := httptest.NewRequest(http.MethodGet, "/api/v1/barrier/recovery-keys", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp map[string]interface{}
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, false, resp["has_recovery_keys"])
	})

	t.Run("GET has_recovery_keys returns true after generation", func(t *testing.T) {
		server, _, _ := createTestServerWithShamirBarrier(t)
		defer xkms.Reset()

		// Generate recovery keys first
		genBody, _ := json.Marshal(BarrierGenerateRecoveryKeysRequest{Threshold: 2, Total: 3})
		genReq := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/recovery-keys/generate", bytes.NewReader(genBody))
		genW := httptest.NewRecorder()
		server.handler.ServeHTTP(genW, genReq)
		require.Equal(t, http.StatusOK, genW.Code)

		// Check if they exist
		req := httptest.NewRequest(http.MethodGet, "/api/v1/barrier/recovery-keys", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp map[string]interface{}
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, true, resp["has_recovery_keys"])
	})

	t.Run("DELETE removes recovery keys", func(t *testing.T) {
		server, _, _ := createTestServerWithShamirBarrier(t)
		defer xkms.Reset()

		// Generate recovery keys first
		genBody, _ := json.Marshal(BarrierGenerateRecoveryKeysRequest{Threshold: 2, Total: 3})
		genReq := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/recovery-keys/generate", bytes.NewReader(genBody))
		genW := httptest.NewRecorder()
		server.handler.ServeHTTP(genW, genReq)
		require.Equal(t, http.StatusOK, genW.Code)

		// Delete them
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/barrier/recovery-keys", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp map[string]interface{}
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, true, resp["success"])

		// Verify deleted
		checkReq := httptest.NewRequest(http.MethodGet, "/api/v1/barrier/recovery-keys", nil)
		checkW := httptest.NewRecorder()
		server.handler.ServeHTTP(checkW, checkReq)
		assert.Equal(t, http.StatusOK, checkW.Code)

		var checkResp map[string]interface{}
		err = json.NewDecoder(checkW.Body).Decode(&checkResp)
		require.NoError(t, err)
		assert.Equal(t, false, checkResp["has_recovery_keys"])
	})

	t.Run("POST method not allowed for recovery-keys dispatch", func(t *testing.T) {
		server, _, _ := createTestServerWithShamirBarrier(t)
		defer xkms.Reset()

		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/recovery-keys", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("barrier not configured returns service unavailable", func(t *testing.T) {
		server := createTestServerNoBarrier(t)
		defer xkms.Reset()

		req := httptest.NewRequest(http.MethodGet, "/api/v1/barrier/recovery-keys", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("sealed barrier returns conflict for has check", func(t *testing.T) {
		server, _, barrier := createTestServerWithShamirBarrier(t)
		defer xkms.Reset()

		err := barrier.Seal()
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/barrier/recovery-keys", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusConflict, w.Code)
	})

	t.Run("sealed barrier returns conflict for delete", func(t *testing.T) {
		server, _, barrier := createTestServerWithShamirBarrier(t)
		defer xkms.Reset()

		err := barrier.Seal()
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/barrier/recovery-keys", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusConflict, w.Code)
	})
}

// --- Error mapping tests ---

func TestBarrierShamirErrorMapping(t *testing.T) {
	t.Run("sendBarrierError maps Shamir errors correctly", func(t *testing.T) {
		xkms.Reset()
		mockKS := xkmsmocks.NewMockKeyStore()
		err := xkms.Initialize(&xkms.ServiceConfig{
			Backends:       map[string]xkms.Backend{"software": mockKS},
			DefaultBackend: "software",
		})
		require.NoError(t, err)
		defer xkms.Reset()

		server, err := NewServer(&Config{
			Addr:          "localhost:8444",
			Authenticator: auth.NewNoOpAuthenticator(),
			Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		})
		require.NoError(t, err)

		tests := []struct {
			name     string
			err      error
			expected int
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
			{"RecoveryKeysNotFound", seal.ErrRecoveryKeysNotFound, http.StatusNotFound},
			{"RootTokenVerificationFailed", seal.ErrRootTokenVerificationFailed, http.StatusUnauthorized},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				w := httptest.NewRecorder()
				sendBarrierError(server, w, tc.err)
				assert.Equal(t, tc.expected, w.Code)
			})
		}
	})
}

// --- Route dispatch tests ---

func TestBarrierShamirRouteDispatch(t *testing.T) {
	t.Run("unknown barrier operation returns not found", func(t *testing.T) {
		server, _, _ := createTestServerWithShamirBarrier(t)
		defer xkms.Reset()

		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/unknown-op", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)

		var resp ErrorResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Contains(t, resp.Message, "unknown barrier operation")
	})

	t.Run("all new routes are registered", func(t *testing.T) {
		server, _, _ := createTestServerWithShamirBarrier(t)
		defer xkms.Reset()

		routes := []struct {
			method string
			path   string
		}{
			{http.MethodPost, "/api/v1/barrier/initialize-shamir"},
			{http.MethodPost, "/api/v1/barrier/unseal-share"},
			{http.MethodPost, "/api/v1/barrier/unseal-shares"},
			{http.MethodPost, "/api/v1/barrier/rekey"},
			{http.MethodPost, "/api/v1/barrier/root-token"},
			{http.MethodGet, "/api/v1/barrier/shamir/shares"},
			{http.MethodPost, "/api/v1/barrier/shamir/verify"},
			{http.MethodPost, "/api/v1/barrier/recovery-keys/generate"},
			{http.MethodPost, "/api/v1/barrier/recovery-keys/recover"},
			{http.MethodGet, "/api/v1/barrier/recovery-keys"},
			{http.MethodDelete, "/api/v1/barrier/recovery-keys"},
			{http.MethodDelete, "/api/v1/barrier/shamir/shares/1"},
		}

		for _, route := range routes {
			t.Run(route.method+" "+route.path, func(t *testing.T) {
				var body io.Reader
				if route.method == http.MethodPost {
					body = strings.NewReader("{}")
				}

				req := httptest.NewRequest(route.method, route.path, body)
				w := httptest.NewRecorder()
				server.handler.ServeHTTP(w, req)

				// Should NOT be 404 (unknown operation); any other error is fine
				// because the handler was found and executed.
				assert.NotEqual(t, http.StatusNotFound, w.Code,
					"route %s %s should be registered", route.method, route.path)
			})
		}
	})
}

// --- Request/Response type serialization tests ---

func TestBarrierShamirRequestResponseTypes(t *testing.T) {
	t.Run("BarrierInitializeShamirRequest JSON round trip", func(t *testing.T) {
		req := BarrierInitializeShamirRequest{Secret: "my-secret"}
		data, err := json.Marshal(req)
		require.NoError(t, err)

		var decoded BarrierInitializeShamirRequest
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)
		assert.Equal(t, req.Secret, decoded.Secret)
	})

	t.Run("BarrierInitializeShamirRequest omitempty secret", func(t *testing.T) {
		req := BarrierInitializeShamirRequest{}
		data, err := json.Marshal(req)
		require.NoError(t, err)
		assert.NotContains(t, string(data), "secret")
	})

	t.Run("BarrierUnsealShareRequest JSON round trip", func(t *testing.T) {
		req := BarrierUnsealShareRequest{Share: "share-value"}
		data, err := json.Marshal(req)
		require.NoError(t, err)

		var decoded BarrierUnsealShareRequest
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)
		assert.Equal(t, req.Share, decoded.Share)
	})

	t.Run("BarrierUnsealSharesRequest JSON round trip", func(t *testing.T) {
		req := BarrierUnsealSharesRequest{Shares: []string{"s1", "s2", "s3"}}
		data, err := json.Marshal(req)
		require.NoError(t, err)

		var decoded BarrierUnsealSharesRequest
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)
		assert.Equal(t, req.Shares, decoded.Shares)
	})

	t.Run("BarrierRekeyRequest JSON round trip", func(t *testing.T) {
		req := BarrierRekeyRequest{Threshold: 3, Total: 5}
		data, err := json.Marshal(req)
		require.NoError(t, err)

		var decoded BarrierRekeyRequest
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)
		assert.Equal(t, req.Threshold, decoded.Threshold)
		assert.Equal(t, req.Total, decoded.Total)
	})

	t.Run("BarrierGenerateRecoveryKeysRequest JSON round trip", func(t *testing.T) {
		req := BarrierGenerateRecoveryKeysRequest{Threshold: 2, Total: 4}
		data, err := json.Marshal(req)
		require.NoError(t, err)

		var decoded BarrierGenerateRecoveryKeysRequest
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)
		assert.Equal(t, req.Threshold, decoded.Threshold)
		assert.Equal(t, req.Total, decoded.Total)
	})

	t.Run("BarrierRecoverWithKeysRequest JSON round trip", func(t *testing.T) {
		req := BarrierRecoverWithKeysRequest{Keys: []string{"k1", "k2"}}
		data, err := json.Marshal(req)
		require.NoError(t, err)

		var decoded BarrierRecoverWithKeysRequest
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)
		assert.Equal(t, req.Keys, decoded.Keys)
	})

	t.Run("BarrierGenerateRootTokenRequest JSON round trip", func(t *testing.T) {
		req := BarrierGenerateRootTokenRequest{Shares: []string{"s1", "s2"}}
		data, err := json.Marshal(req)
		require.NoError(t, err)

		var decoded BarrierGenerateRootTokenRequest
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)
		assert.Equal(t, req.Shares, decoded.Shares)
	})

	t.Run("BarrierShamirSharesResponse JSON round trip", func(t *testing.T) {
		resp := BarrierShamirSharesResponse{Count: 5, Threshold: 3, Total: 5}
		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var decoded BarrierShamirSharesResponse
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)
		assert.Equal(t, resp.Count, decoded.Count)
		assert.Equal(t, resp.Threshold, decoded.Threshold)
		assert.Equal(t, resp.Total, decoded.Total)
	})
}
