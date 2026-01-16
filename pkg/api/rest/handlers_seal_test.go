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

package rest

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSealHandler tests the POST /api/v1/seal endpoint
func TestSealHandler(t *testing.T) {
	t.Run("seals data successfully with valid request", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")

		// Configure mock to support sealing
		expectedCiphertext := []byte("encrypted-data")
		expectedNonce := []byte("test-nonce")
		expectedTag := []byte("test-tag")
		ks.SealFunc = func(ctx context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
			return &types.SealedData{
				Backend:    types.BackendTypeSoftware,
				Ciphertext: expectedCiphertext,
				Nonce:      expectedNonce,
				Tag:        expectedTag,
				Metadata:   map[string][]byte{"key": []byte("value")},
			}, nil
		}

		ctx := newTestHandlerContext()
		reqBody := `{"backend":"test-backend","data":"dGVzdC1kYXRh"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/seal", strings.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		ctx.SealHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

		var resp SealResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, string(types.BackendTypeSoftware), resp.Backend)
		assert.Equal(t, expectedCiphertext, resp.Ciphertext)
		assert.Equal(t, expectedNonce, resp.Nonce)
		assert.Equal(t, expectedTag, resp.Tag)
		assert.Equal(t, 1, ks.SealCalls)
	})

	t.Run("seals data with optional key_id", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")

		var capturedOpts *types.SealOptions
		ks.SealFunc = func(ctx context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
			capturedOpts = opts
			return &types.SealedData{
				Backend:    types.BackendTypeSoftware,
				Ciphertext: []byte("encrypted"),
			}, nil
		}

		ctx := newTestHandlerContext()
		reqBody := `{"backend":"test-backend","data":"dGVzdA==","key_id":"my-seal-key"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/seal", strings.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		ctx.SealHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		require.NotNil(t, capturedOpts)
		require.NotNil(t, capturedOpts.KeyAttributes)
		assert.Equal(t, "my-seal-key", capturedOpts.KeyAttributes.CN)
	})

	t.Run("seals data with AAD (additional authenticated data)", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")

		var capturedOpts *types.SealOptions
		ks.SealFunc = func(ctx context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
			capturedOpts = opts
			return &types.SealedData{
				Backend:    types.BackendTypeSoftware,
				Ciphertext: []byte("encrypted"),
			}, nil
		}

		ctx := newTestHandlerContext()
		// AAD is base64 encoded: "context-data" = "Y29udGV4dC1kYXRh"
		reqBody := `{"backend":"test-backend","data":"dGVzdA==","aad":"Y29udGV4dC1kYXRh"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/seal", strings.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		ctx.SealHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		require.NotNil(t, capturedOpts)
		assert.Equal(t, []byte("context-data"), capturedOpts.AAD)
	})

	t.Run("returns error for invalid JSON", func(t *testing.T) {
		setupTestService(t, "test-backend")

		ctx := newTestHandlerContext()
		reqBody := `{"backend":123, invalid json}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/seal", strings.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		ctx.SealHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var resp ErrorResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Contains(t, resp.Error, "invalid request")
	})

	t.Run("returns error for missing backend", func(t *testing.T) {
		setupTestService(t, "test-backend")

		ctx := newTestHandlerContext()
		reqBody := `{"data":"dGVzdA=="}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/seal", strings.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		ctx.SealHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var resp ErrorResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Contains(t, resp.Error, "missing backend")
	})

	t.Run("returns error for empty backend string", func(t *testing.T) {
		setupTestService(t, "test-backend")

		ctx := newTestHandlerContext()
		reqBody := `{"backend":"","data":"dGVzdA=="}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/seal", strings.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		ctx.SealHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var resp ErrorResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Contains(t, resp.Error, "missing backend")
	})

	t.Run("returns error for invalid backend name", func(t *testing.T) {
		setupTestService(t, "test-backend")

		ctx := newTestHandlerContext()
		reqBody := `{"backend":"invalid_BACKEND!","data":"dGVzdA=="}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/seal", strings.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		ctx.SealHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var resp ErrorResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Contains(t, resp.Error, "invalid backend")
	})

	t.Run("returns error for missing data", func(t *testing.T) {
		setupTestService(t, "test-backend")

		ctx := newTestHandlerContext()
		reqBody := `{"backend":"test-backend"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/seal", strings.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		ctx.SealHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var resp ErrorResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Contains(t, resp.Error, "missing data")
	})

	t.Run("returns error for empty data", func(t *testing.T) {
		setupTestService(t, "test-backend")

		ctx := newTestHandlerContext()
		reqBody := `{"backend":"test-backend","data":""}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/seal", strings.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		ctx.SealHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var resp ErrorResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Contains(t, resp.Error, "missing data")
	})

	t.Run("returns error for invalid key_id", func(t *testing.T) {
		setupTestService(t, "test-backend")

		ctx := newTestHandlerContext()
		// key_id with path traversal attempt
		reqBody := `{"backend":"test-backend","data":"dGVzdA==","key_id":"../../../etc/passwd"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/seal", strings.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		ctx.SealHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var resp ErrorResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Contains(t, resp.Error, "invalid key ID")
	})

	t.Run("returns error when seal operation fails", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")

		ks.SealFunc = func(ctx context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
			return nil, errors.New("seal operation failed: TPM not available")
		}

		ctx := newTestHandlerContext()
		reqBody := `{"backend":"test-backend","data":"dGVzdA=="}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/seal", strings.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		ctx.SealHandler(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var resp ErrorResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Contains(t, resp.Error, "TPM not available")
	})
}

// TestUnsealHandler tests the POST /api/v1/unseal endpoint
func TestUnsealHandler(t *testing.T) {
	t.Run("unseals data successfully with valid request", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")

		expectedPlaintext := []byte("decrypted-secret")
		ks.UnsealFunc = func(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
			return expectedPlaintext, nil
		}

		ctx := newTestHandlerContext()
		reqBody := `{"backend":"test-backend","ciphertext":"ZW5jcnlwdGVkLWRhdGE=","nonce":"dGVzdC1ub25jZQ==","tag":"dGVzdC10YWc="}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/unseal", strings.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		ctx.UnsealHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

		var resp UnsealResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, expectedPlaintext, resp.Plaintext)
		assert.Equal(t, 1, ks.UnsealCalls)
	})

	t.Run("unseals data with optional key_id", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")

		var capturedOpts *types.UnsealOptions
		ks.UnsealFunc = func(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
			capturedOpts = opts
			return []byte("decrypted"), nil
		}

		ctx := newTestHandlerContext()
		reqBody := `{"backend":"test-backend","ciphertext":"ZW5jcnlwdGVk","key_id":"my-seal-key"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/unseal", strings.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		ctx.UnsealHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		require.NotNil(t, capturedOpts)
		require.NotNil(t, capturedOpts.KeyAttributes)
		assert.Equal(t, "my-seal-key", capturedOpts.KeyAttributes.CN)
	})

	t.Run("unseals data with AAD", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")

		var capturedOpts *types.UnsealOptions
		ks.UnsealFunc = func(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
			capturedOpts = opts
			return []byte("decrypted"), nil
		}

		ctx := newTestHandlerContext()
		// AAD is base64 encoded: "context-data" = "Y29udGV4dC1kYXRh"
		reqBody := `{"backend":"test-backend","ciphertext":"ZW5jcnlwdGVk","aad":"Y29udGV4dC1kYXRh"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/unseal", strings.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		ctx.UnsealHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		require.NotNil(t, capturedOpts)
		assert.Equal(t, []byte("context-data"), capturedOpts.AAD)
	})

	t.Run("unseals data with metadata", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")

		var capturedSealed *types.SealedData
		ks.UnsealFunc = func(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
			capturedSealed = sealed
			return []byte("decrypted"), nil
		}

		ctx := newTestHandlerContext()
		reqBody := `{"backend":"test-backend","ciphertext":"ZW5jcnlwdGVk","metadata":{"tpm:handle":"aGFuZGxl"}}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/unseal", strings.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		ctx.UnsealHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		require.NotNil(t, capturedSealed)
		assert.NotNil(t, capturedSealed.Metadata)
		assert.Equal(t, []byte("handle"), capturedSealed.Metadata["tpm:handle"])
	})

	t.Run("returns error for invalid JSON", func(t *testing.T) {
		setupTestService(t, "test-backend")

		ctx := newTestHandlerContext()
		reqBody := `{invalid json`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/unseal", strings.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		ctx.UnsealHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var resp ErrorResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Contains(t, resp.Error, "invalid request")
	})

	t.Run("returns error for missing backend", func(t *testing.T) {
		setupTestService(t, "test-backend")

		ctx := newTestHandlerContext()
		reqBody := `{"ciphertext":"ZW5jcnlwdGVk"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/unseal", strings.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		ctx.UnsealHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var resp ErrorResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Contains(t, resp.Error, "missing backend")
	})

	t.Run("returns error for empty backend", func(t *testing.T) {
		setupTestService(t, "test-backend")

		ctx := newTestHandlerContext()
		reqBody := `{"backend":"","ciphertext":"ZW5jcnlwdGVk"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/unseal", strings.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		ctx.UnsealHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var resp ErrorResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Contains(t, resp.Error, "missing backend")
	})

	t.Run("returns error for invalid backend name", func(t *testing.T) {
		setupTestService(t, "test-backend")

		ctx := newTestHandlerContext()
		reqBody := `{"backend":"INVALID$BACKEND","ciphertext":"ZW5jcnlwdGVk"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/unseal", strings.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		ctx.UnsealHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var resp ErrorResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Contains(t, resp.Error, "invalid backend")
	})

	t.Run("returns error for missing ciphertext", func(t *testing.T) {
		setupTestService(t, "test-backend")

		ctx := newTestHandlerContext()
		reqBody := `{"backend":"test-backend"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/unseal", strings.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		ctx.UnsealHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var resp ErrorResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Contains(t, resp.Error, "missing ciphertext")
	})

	t.Run("returns error for empty ciphertext", func(t *testing.T) {
		setupTestService(t, "test-backend")

		ctx := newTestHandlerContext()
		reqBody := `{"backend":"test-backend","ciphertext":""}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/unseal", strings.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		ctx.UnsealHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var resp ErrorResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Contains(t, resp.Error, "missing ciphertext")
	})

	t.Run("returns error for invalid key_id", func(t *testing.T) {
		setupTestService(t, "test-backend")

		ctx := newTestHandlerContext()
		reqBody := `{"backend":"test-backend","ciphertext":"ZW5jcnlwdGVk","key_id":"../../secret"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/unseal", strings.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		ctx.UnsealHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var resp ErrorResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Contains(t, resp.Error, "invalid key ID")
	})

	t.Run("returns error for non-existent backend", func(t *testing.T) {
		setupTestService(t, "test-backend")

		ctx := newTestHandlerContext()
		reqBody := `{"backend":"nonexistent-backend","ciphertext":"ZW5jcnlwdGVk"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/unseal", strings.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		ctx.UnsealHandler(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)

		var resp ErrorResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Contains(t, resp.Error, "backend not found")
	})

	t.Run("returns error when unseal operation fails", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")

		ks.UnsealFunc = func(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
			return nil, errors.New("unseal failed: authentication error")
		}

		ctx := newTestHandlerContext()
		reqBody := `{"backend":"test-backend","ciphertext":"ZW5jcnlwdGVk"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/unseal", strings.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		ctx.UnsealHandler(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var resp ErrorResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Contains(t, resp.Error, "authentication error")
	})
}

// TestCanSealHandler tests the GET /api/v1/can-seal endpoint
func TestCanSealHandler(t *testing.T) {
	t.Run("returns true when specific backend supports sealing", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")

		ks.CanSealFunc = func() bool {
			return true
		}

		ctx := newTestHandlerContext()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/can-seal?backend=test-backend", nil)
		w := httptest.NewRecorder()

		ctx.CanSealHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

		var resp CanSealResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.True(t, resp.CanSeal)
		assert.Equal(t, "test-backend", resp.Backend)
		assert.Equal(t, 1, ks.CanSealCalls)
	})

	t.Run("returns false when specific backend does not support sealing", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")

		ks.CanSealFunc = func() bool {
			return false
		}

		ctx := newTestHandlerContext()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/can-seal?backend=test-backend", nil)
		w := httptest.NewRecorder()

		ctx.CanSealHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp CanSealResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.False(t, resp.CanSeal)
		assert.Equal(t, "test-backend", resp.Backend)
	})

	t.Run("uses default backend when no backend query param provided", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")

		ks.CanSealFunc = func() bool {
			return true
		}

		ctx := newTestHandlerContext()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/can-seal", nil)
		w := httptest.NewRecorder()

		ctx.CanSealHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp CanSealResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.True(t, resp.CanSeal)
		// Backend should be empty when using default
		assert.Empty(t, resp.Backend)
		assert.Equal(t, 1, ks.CanSealCalls)
	})

	t.Run("uses default backend when empty backend query param", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")

		ks.CanSealFunc = func() bool {
			return false
		}

		ctx := newTestHandlerContext()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/can-seal?backend=", nil)
		w := httptest.NewRecorder()

		ctx.CanSealHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp CanSealResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.False(t, resp.CanSeal)
		assert.Empty(t, resp.Backend)
	})

	t.Run("returns error for invalid backend name", func(t *testing.T) {
		setupTestService(t, "test-backend")

		ctx := newTestHandlerContext()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/can-seal?backend=INVALID_Backend!", nil)
		w := httptest.NewRecorder()

		ctx.CanSealHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var resp ErrorResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Contains(t, resp.Error, "invalid backend")
	})

	t.Run("returns false for non-existent backend", func(t *testing.T) {
		setupTestService(t, "test-backend")

		ctx := newTestHandlerContext()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/can-seal?backend=nonexistent", nil)
		w := httptest.NewRecorder()

		ctx.CanSealHandler(w, req)

		// CanSeal returns false when backend not found (no error)
		assert.Equal(t, http.StatusOK, w.Code)

		var resp CanSealResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.False(t, resp.CanSeal)
		assert.Equal(t, "nonexistent", resp.Backend)
	})

	t.Run("handles service not initialized", func(t *testing.T) {
		// Reset without setting up a new service
		keychain.Reset()

		ctx := newTestHandlerContext()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/can-seal", nil)
		w := httptest.NewRecorder()

		ctx.CanSealHandler(w, req)

		// When service is not initialized, CanSeal returns false
		assert.Equal(t, http.StatusOK, w.Code)

		var resp CanSealResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.False(t, resp.CanSeal)
	})
}

// TestSealUnsealIntegration tests the seal and unseal handlers together
func TestSealUnsealIntegration(t *testing.T) {
	t.Run("sealed data can be unsealed", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")

		// Store the sealed data for verification
		var sealedData *types.SealedData
		plaintext := []byte("secret-data-to-seal")

		ks.SealFunc = func(ctx context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
			sealedData = &types.SealedData{
				Backend:    types.BackendTypeSoftware,
				Ciphertext: []byte("encrypted-" + string(data)),
				Nonce:      []byte("nonce"),
				Tag:        []byte("tag"),
			}
			return sealedData, nil
		}

		ks.UnsealFunc = func(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
			// Verify the sealed data matches what we sealed
			if string(sealed.Ciphertext) != string(sealedData.Ciphertext) {
				return nil, errors.New("ciphertext mismatch")
			}
			return plaintext, nil
		}

		ctx := newTestHandlerContext()

		// First, seal the data
		sealReqBody := `{"backend":"test-backend","data":"c2VjcmV0LWRhdGEtdG8tc2VhbA=="}`
		sealReq := httptest.NewRequest(http.MethodPost, "/api/v1/seal", strings.NewReader(sealReqBody))
		sealReq.Header.Set("Content-Type", "application/json")
		sealW := httptest.NewRecorder()

		ctx.SealHandler(sealW, sealReq)
		assert.Equal(t, http.StatusOK, sealW.Code)

		var sealResp SealResponse
		err := json.NewDecoder(sealW.Body).Decode(&sealResp)
		require.NoError(t, err)

		// Now unseal using the sealed response
		unsealReqBody := `{"backend":"test-backend","ciphertext":"ZW5jcnlwdGVkLXNlY3JldC1kYXRhLXRvLXNlYWw=","nonce":"bm9uY2U=","tag":"dGFn"}`
		unsealReq := httptest.NewRequest(http.MethodPost, "/api/v1/unseal", strings.NewReader(unsealReqBody))
		unsealReq.Header.Set("Content-Type", "application/json")
		unsealW := httptest.NewRecorder()

		ctx.UnsealHandler(unsealW, unsealReq)
		assert.Equal(t, http.StatusOK, unsealW.Code)

		var unsealResp UnsealResponse
		err = json.NewDecoder(unsealW.Body).Decode(&unsealResp)
		require.NoError(t, err)
		assert.Equal(t, plaintext, unsealResp.Plaintext)
	})
}

// TestSealHandlerEdgeCases tests edge cases for the seal handler
func TestSealHandlerEdgeCases(t *testing.T) {
	t.Run("handles large data payload", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")

		ks.SealFunc = func(ctx context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
			return &types.SealedData{
				Backend:    types.BackendTypeSoftware,
				Ciphertext: data, // Echo back the data
			}, nil
		}

		ctx := newTestHandlerContext()
		// Large data (1KB base64 encoded)
		largeData := strings.Repeat("A", 1000)
		reqBody := `{"backend":"test-backend","data":"` + largeData + `"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/seal", strings.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		ctx.SealHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("handles special characters in key_id", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")

		ks.SealFunc = func(ctx context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
			return &types.SealedData{
				Backend:    types.BackendTypeSoftware,
				Ciphertext: []byte("encrypted"),
			}, nil
		}

		ctx := newTestHandlerContext()
		// Valid key_id with allowed special characters
		reqBody := `{"backend":"test-backend","data":"dGVzdA==","key_id":"my-key_v1.0"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/seal", strings.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		ctx.SealHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("handles hyphenated backend names", func(t *testing.T) {
		ks := setupTestService(t, "my-tpm2-backend")

		ks.SealFunc = func(ctx context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
			return &types.SealedData{
				Backend:    types.BackendTypeTPM2,
				Ciphertext: []byte("encrypted"),
			}, nil
		}

		ctx := newTestHandlerContext()
		reqBody := `{"backend":"my-tpm2-backend","data":"dGVzdA=="}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/seal", strings.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		ctx.SealHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

// TestUnsealHandlerEdgeCases tests edge cases for the unseal handler
func TestUnsealHandlerEdgeCases(t *testing.T) {
	t.Run("handles unseal with all optional fields", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")

		var capturedSealed *types.SealedData
		var capturedOpts *types.UnsealOptions
		ks.UnsealFunc = func(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
			capturedSealed = sealed
			capturedOpts = opts
			return []byte("decrypted"), nil
		}

		ctx := newTestHandlerContext()
		reqBody := `{
			"backend":"test-backend",
			"ciphertext":"Y2lwaGVy",
			"nonce":"bm9uY2U=",
			"tag":"dGFn",
			"key_id":"my-key",
			"aad":"YWFk",
			"metadata":{"custom":"dmFsdWU="}
		}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/unseal", strings.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		ctx.UnsealHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		require.NotNil(t, capturedSealed)
		assert.Equal(t, []byte("cipher"), capturedSealed.Ciphertext)
		assert.Equal(t, []byte("nonce"), capturedSealed.Nonce)
		assert.Equal(t, []byte("tag"), capturedSealed.Tag)
		assert.Equal(t, "my-key", capturedSealed.KeyID)
		require.NotNil(t, capturedOpts)
		assert.Equal(t, []byte("aad"), capturedOpts.AAD)
		require.NotNil(t, capturedOpts.KeyAttributes)
		assert.Equal(t, "my-key", capturedOpts.KeyAttributes.CN)
	})

	t.Run("handles unseal with minimal fields", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")

		ks.UnsealFunc = func(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
			return []byte("decrypted"), nil
		}

		ctx := newTestHandlerContext()
		// Minimal required fields only
		reqBody := `{"backend":"test-backend","ciphertext":"Y2lwaGVy"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/unseal", strings.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		ctx.UnsealHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}
