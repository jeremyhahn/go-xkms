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

package quic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/adapters/auth"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	keychainmocks "github.com/jeremyhahn/go-keychain/pkg/keychain/mocks"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestServerWithSealSupport creates a test server with a mock keystore
// that supports sealing operations.
func createTestServerWithSealSupport(t *testing.T) (*Server, *keychainmocks.MockKeyStore) {
	t.Helper()

	keychain.Reset()

	mockKS := keychainmocks.NewMockKeyStore()

	// Configure the mock to support sealing
	mockKS.CanSealFunc = func() bool {
		return true
	}

	// Configure successful seal operation
	mockKS.SealFunc = func(ctx context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
		return &types.SealedData{
			Backend:    types.BackendTypeSoftware,
			Ciphertext: append([]byte("sealed:"), data...),
			Nonce:      []byte("test-nonce-12345"),
			Tag:        []byte("test-tag"),
			Metadata: map[string][]byte{
				"test": []byte("metadata"),
			},
		}, nil
	}

	// Configure successful unseal operation
	mockKS.UnsealFunc = func(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
		if bytes.HasPrefix(sealed.Ciphertext, []byte("sealed:")) {
			return sealed.Ciphertext[7:], nil
		}
		return nil, errors.New("invalid sealed data")
	}

	// Configure the backend mock to return correct type
	mockKS.BackendMock.TypeFunc = func() types.BackendType {
		return types.BackendTypeSoftware
	}

	err := keychain.Initialize(&keychain.ServiceConfig{
		Backends: map[string]keychain.KeyStore{
			"software": mockKS,
		},
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

	return server, mockKS
}

// TestHandleSeal tests the handleSeal handler
func TestHandleSeal(t *testing.T) {
	t.Run("POST seals data successfully", func(t *testing.T) {
		server, mockKS := createTestServerWithSealSupport(t)
		defer keychain.Reset()

		testData := []byte("secret data to seal")
		reqBody := SealRequest{
			Backend: "software",
			KeyID:   "test-key",
			Data:    testData,
			AAD:     []byte("additional auth data"),
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/seal", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp SealResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)

		assert.Equal(t, string(types.BackendTypeSoftware), resp.Backend)
		assert.NotEmpty(t, resp.Ciphertext)
		assert.NotEmpty(t, resp.Nonce)
		assert.NotEmpty(t, resp.Tag)
		assert.NotNil(t, resp.Metadata)
		assert.Equal(t, 1, mockKS.SealCalls)
	})

	t.Run("POST seals data without KeyID", func(t *testing.T) {
		server, mockKS := createTestServerWithSealSupport(t)
		defer keychain.Reset()

		testData := []byte("secret data")
		reqBody := SealRequest{
			Backend: "software",
			Data:    testData,
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/seal", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, 1, mockKS.SealCalls)
	})

	t.Run("POST with invalid JSON returns bad request", func(t *testing.T) {
		server, _ := createTestServerWithSealSupport(t)
		defer keychain.Reset()

		req := httptest.NewRequest(http.MethodPost, "/api/v1/seal", strings.NewReader("{invalid json}"))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var resp ErrorResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Contains(t, resp.Message, "invalid request")
	})

	t.Run("POST with missing backend returns bad request", func(t *testing.T) {
		server, _ := createTestServerWithSealSupport(t)
		defer keychain.Reset()

		reqBody := SealRequest{
			Data: []byte("test data"),
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/seal", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var resp ErrorResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Contains(t, resp.Message, "backend is required")
	})

	t.Run("POST with missing data returns bad request", func(t *testing.T) {
		server, _ := createTestServerWithSealSupport(t)
		defer keychain.Reset()

		reqBody := SealRequest{
			Backend: "software",
			KeyID:   "test-key",
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/seal", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var resp ErrorResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Contains(t, resp.Message, "data is required")
	})

	t.Run("POST with empty data returns bad request", func(t *testing.T) {
		server, _ := createTestServerWithSealSupport(t)
		defer keychain.Reset()

		reqBody := SealRequest{
			Backend: "software",
			KeyID:   "test-key",
			Data:    []byte{},
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/seal", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var resp ErrorResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Contains(t, resp.Message, "data is required")
	})

	t.Run("POST with seal error returns internal server error", func(t *testing.T) {
		server, mockKS := createTestServerWithSealSupport(t)
		defer keychain.Reset()

		// Configure mock to return an error
		mockKS.SealFunc = func(ctx context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
			return nil, errors.New("seal operation failed")
		}

		reqBody := SealRequest{
			Backend: "software",
			Data:    []byte("test data"),
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/seal", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var resp ErrorResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Contains(t, resp.Message, "failed to seal data")
	})

	t.Run("GET method not allowed", func(t *testing.T) {
		server, _ := createTestServerWithSealSupport(t)
		defer keychain.Reset()

		req := httptest.NewRequest(http.MethodGet, "/api/v1/seal", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("PUT method not allowed", func(t *testing.T) {
		server, _ := createTestServerWithSealSupport(t)
		defer keychain.Reset()

		req := httptest.NewRequest(http.MethodPut, "/api/v1/seal", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("DELETE method not allowed", func(t *testing.T) {
		server, _ := createTestServerWithSealSupport(t)
		defer keychain.Reset()

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/seal", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})
}

// TestHandleUnseal tests the handleUnseal handler
func TestHandleUnseal(t *testing.T) {
	t.Run("POST unseals data successfully", func(t *testing.T) {
		server, mockKS := createTestServerWithSealSupport(t)
		defer keychain.Reset()

		originalData := []byte("original secret data")
		reqBody := UnsealRequest{
			Backend:    "software",
			KeyID:      "test-key",
			Ciphertext: append([]byte("sealed:"), originalData...),
			Nonce:      []byte("test-nonce-12345"),
			Tag:        []byte("test-tag"),
			AAD:        []byte("additional auth data"),
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/unseal", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp UnsealResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)

		assert.Equal(t, originalData, resp.Plaintext)
		assert.Equal(t, 1, mockKS.UnsealCalls)
	})

	t.Run("POST unseals data without KeyID", func(t *testing.T) {
		server, mockKS := createTestServerWithSealSupport(t)
		defer keychain.Reset()

		reqBody := UnsealRequest{
			Backend:    "software",
			Ciphertext: append([]byte("sealed:"), []byte("data")...),
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/unseal", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, 1, mockKS.UnsealCalls)
	})

	t.Run("POST with invalid JSON returns bad request", func(t *testing.T) {
		server, _ := createTestServerWithSealSupport(t)
		defer keychain.Reset()

		req := httptest.NewRequest(http.MethodPost, "/api/v1/unseal", strings.NewReader("{invalid json}"))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var resp ErrorResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Contains(t, resp.Message, "invalid request")
	})

	t.Run("POST with missing backend returns bad request", func(t *testing.T) {
		server, _ := createTestServerWithSealSupport(t)
		defer keychain.Reset()

		reqBody := UnsealRequest{
			Ciphertext: []byte("encrypted data"),
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/unseal", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var resp ErrorResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Contains(t, resp.Message, "backend is required")
	})

	t.Run("POST with missing ciphertext returns bad request", func(t *testing.T) {
		server, _ := createTestServerWithSealSupport(t)
		defer keychain.Reset()

		reqBody := UnsealRequest{
			Backend: "software",
			KeyID:   "test-key",
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/unseal", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var resp ErrorResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Contains(t, resp.Message, "ciphertext is required")
	})

	t.Run("POST with empty ciphertext returns bad request", func(t *testing.T) {
		server, _ := createTestServerWithSealSupport(t)
		defer keychain.Reset()

		reqBody := UnsealRequest{
			Backend:    "software",
			KeyID:      "test-key",
			Ciphertext: []byte{},
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/unseal", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var resp ErrorResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Contains(t, resp.Message, "ciphertext is required")
	})

	t.Run("POST with unseal error returns internal server error", func(t *testing.T) {
		server, mockKS := createTestServerWithSealSupport(t)
		defer keychain.Reset()

		// Configure mock to return an error
		mockKS.UnsealFunc = func(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
			return nil, errors.New("unseal operation failed")
		}

		reqBody := UnsealRequest{
			Backend:    "software",
			Ciphertext: []byte("encrypted data"),
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/unseal", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var resp ErrorResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Contains(t, resp.Message, "failed to unseal data")
	})

	t.Run("GET method not allowed", func(t *testing.T) {
		server, _ := createTestServerWithSealSupport(t)
		defer keychain.Reset()

		req := httptest.NewRequest(http.MethodGet, "/api/v1/unseal", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("PUT method not allowed", func(t *testing.T) {
		server, _ := createTestServerWithSealSupport(t)
		defer keychain.Reset()

		req := httptest.NewRequest(http.MethodPut, "/api/v1/unseal", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})
}

// TestHandleCanSeal tests the handleCanSeal handler
func TestHandleCanSeal(t *testing.T) {
	t.Run("GET with specific backend returns can_seal true", func(t *testing.T) {
		server, _ := createTestServerWithSealSupport(t)
		defer keychain.Reset()

		req := httptest.NewRequest(http.MethodGet, "/api/v1/can_seal?backend=software", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp CanSealResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.True(t, resp.CanSeal)
	})

	t.Run("GET without backend uses default backend", func(t *testing.T) {
		server, _ := createTestServerWithSealSupport(t)
		defer keychain.Reset()

		req := httptest.NewRequest(http.MethodGet, "/api/v1/can_seal", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp CanSealResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.True(t, resp.CanSeal)
	})

	t.Run("POST with specific backend returns can_seal", func(t *testing.T) {
		server, _ := createTestServerWithSealSupport(t)
		defer keychain.Reset()

		reqBody := CanSealRequest{
			Backend: "software",
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/can_seal", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp CanSealResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.True(t, resp.CanSeal)
	})

	t.Run("POST without backend uses default backend", func(t *testing.T) {
		server, _ := createTestServerWithSealSupport(t)
		defer keychain.Reset()

		reqBody := CanSealRequest{}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/can_seal", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp CanSealResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.True(t, resp.CanSeal)
	})

	t.Run("POST with invalid JSON returns bad request", func(t *testing.T) {
		server, _ := createTestServerWithSealSupport(t)
		defer keychain.Reset()

		req := httptest.NewRequest(http.MethodPost, "/api/v1/can_seal", strings.NewReader("{invalid json}"))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var resp ErrorResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Contains(t, resp.Message, "invalid request")
	})

	t.Run("PUT method not allowed", func(t *testing.T) {
		server, _ := createTestServerWithSealSupport(t)
		defer keychain.Reset()

		req := httptest.NewRequest(http.MethodPut, "/api/v1/can_seal", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("DELETE method not allowed", func(t *testing.T) {
		server, _ := createTestServerWithSealSupport(t)
		defer keychain.Reset()

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/can_seal", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("GET returns can_seal false when backend does not support sealing", func(t *testing.T) {
		keychain.Reset()

		mockKS := keychainmocks.NewMockKeyStore()

		// Configure the mock to NOT support sealing
		mockKS.CanSealFunc = func() bool {
			return false
		}

		err := keychain.Initialize(&keychain.ServiceConfig{
			Backends: map[string]keychain.KeyStore{
				"software": mockKS,
			},
			DefaultBackend: "software",
		})
		require.NoError(t, err)
		defer keychain.Reset()

		cfg := &Config{
			Addr:          "localhost:8444",
			Authenticator: auth.NewNoOpAuthenticator(),
			Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		}

		server, err := NewServer(cfg)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/can_seal?backend=software", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp CanSealResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.False(t, resp.CanSeal)
	})
}

// TestSealUnsealRoundTrip tests a complete seal/unseal cycle
func TestSealUnsealRoundTrip(t *testing.T) {
	t.Run("seal then unseal returns original data", func(t *testing.T) {
		server, _ := createTestServerWithSealSupport(t)
		defer keychain.Reset()

		originalData := []byte("this is my secret data that needs protection")

		// Step 1: Seal the data
		sealReqBody := SealRequest{
			Backend: "software",
			KeyID:   "test-key",
			Data:    originalData,
			AAD:     []byte("context"),
		}

		sealBody, err := json.Marshal(sealReqBody)
		require.NoError(t, err)

		sealReq := httptest.NewRequest(http.MethodPost, "/api/v1/seal", bytes.NewReader(sealBody))
		sealReq.Header.Set("Content-Type", "application/json")
		sealW := httptest.NewRecorder()

		server.handler.ServeHTTP(sealW, sealReq)
		assert.Equal(t, http.StatusOK, sealW.Code)

		var sealResp SealResponse
		err = json.NewDecoder(sealW.Body).Decode(&sealResp)
		require.NoError(t, err)

		// Step 2: Unseal the data
		unsealReqBody := UnsealRequest{
			Backend:    "software",
			KeyID:      "test-key",
			Ciphertext: sealResp.Ciphertext,
			Nonce:      sealResp.Nonce,
			Tag:        sealResp.Tag,
			AAD:        []byte("context"),
		}

		unsealBody, err := json.Marshal(unsealReqBody)
		require.NoError(t, err)

		unsealReq := httptest.NewRequest(http.MethodPost, "/api/v1/unseal", bytes.NewReader(unsealBody))
		unsealReq.Header.Set("Content-Type", "application/json")
		unsealW := httptest.NewRecorder()

		server.handler.ServeHTTP(unsealW, unsealReq)
		assert.Equal(t, http.StatusOK, unsealW.Code)

		var unsealResp UnsealResponse
		err = json.NewDecoder(unsealW.Body).Decode(&unsealResp)
		require.NoError(t, err)

		// Verify round-trip preserves data
		assert.Equal(t, originalData, unsealResp.Plaintext)
	})
}

// TestHandleSealWithNonExistentBackend tests seal with an invalid backend
func TestHandleSealWithNonExistentBackend(t *testing.T) {
	t.Run("POST with non-existent backend returns error", func(t *testing.T) {
		server, _ := createTestServerWithSealSupport(t)
		defer keychain.Reset()

		reqBody := SealRequest{
			Backend: "nonexistent-backend",
			Data:    []byte("test data"),
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/seal", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		// The handler should return an error when backend is not found
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// TestHandleUnsealWithNonExistentBackend tests unseal with an invalid backend
func TestHandleUnsealWithNonExistentBackend(t *testing.T) {
	t.Run("POST with non-existent backend returns error", func(t *testing.T) {
		server, _ := createTestServerWithSealSupport(t)
		defer keychain.Reset()

		reqBody := UnsealRequest{
			Backend:    "nonexistent-backend",
			Ciphertext: []byte("encrypted data"),
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/unseal", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		// The handler should return an error when backend is not found
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// TestSealRequestTypes verifies proper request/response type handling
func TestSealRequestTypes(t *testing.T) {
	t.Run("SealRequest with all fields populated", func(t *testing.T) {
		reqBody := SealRequest{
			Backend: "software",
			KeyID:   "test-key",
			Data:    []byte("test data"),
			AAD:     []byte("additional data"),
		}

		data, err := json.Marshal(reqBody)
		require.NoError(t, err)

		var decoded SealRequest
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, reqBody.Backend, decoded.Backend)
		assert.Equal(t, reqBody.KeyID, decoded.KeyID)
		assert.Equal(t, reqBody.Data, decoded.Data)
		assert.Equal(t, reqBody.AAD, decoded.AAD)
	})

	t.Run("UnsealRequest with all fields populated", func(t *testing.T) {
		reqBody := UnsealRequest{
			Backend:    "software",
			KeyID:      "test-key",
			Ciphertext: []byte("ciphertext"),
			Nonce:      []byte("nonce"),
			Tag:        []byte("tag"),
			AAD:        []byte("aad"),
		}

		data, err := json.Marshal(reqBody)
		require.NoError(t, err)

		var decoded UnsealRequest
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, reqBody.Backend, decoded.Backend)
		assert.Equal(t, reqBody.KeyID, decoded.KeyID)
		assert.Equal(t, reqBody.Ciphertext, decoded.Ciphertext)
		assert.Equal(t, reqBody.Nonce, decoded.Nonce)
		assert.Equal(t, reqBody.Tag, decoded.Tag)
		assert.Equal(t, reqBody.AAD, decoded.AAD)
	})

	t.Run("CanSealRequest JSON serialization", func(t *testing.T) {
		reqBody := CanSealRequest{
			Backend: "software",
		}

		data, err := json.Marshal(reqBody)
		require.NoError(t, err)

		var decoded CanSealRequest
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, reqBody.Backend, decoded.Backend)
	})

	t.Run("SealResponse JSON serialization", func(t *testing.T) {
		resp := SealResponse{
			Backend:    string(types.BackendTypeSoftware),
			Ciphertext: []byte("ciphertext"),
			Nonce:      []byte("nonce"),
			Tag:        []byte("tag"),
			Metadata: map[string][]byte{
				"key": []byte("value"),
			},
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var decoded SealResponse
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, resp.Backend, decoded.Backend)
		assert.Equal(t, resp.Ciphertext, decoded.Ciphertext)
		assert.Equal(t, resp.Nonce, decoded.Nonce)
		assert.Equal(t, resp.Tag, decoded.Tag)
		assert.Equal(t, resp.Metadata["key"], decoded.Metadata["key"])
	})

	t.Run("UnsealResponse JSON serialization", func(t *testing.T) {
		resp := UnsealResponse{
			Plaintext: []byte("plaintext data"),
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var decoded UnsealResponse
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, resp.Plaintext, decoded.Plaintext)
	})

	t.Run("CanSealResponse JSON serialization", func(t *testing.T) {
		resp := CanSealResponse{
			CanSeal: true,
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var decoded CanSealResponse
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, resp.CanSeal, decoded.CanSeal)
	})
}
