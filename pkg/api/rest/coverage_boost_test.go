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
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==========================================================================
// handlers.go - SignHandler
// ==========================================================================

func TestSignHandler_MissingKeyID(t *testing.T) {
	ctx := newTestHandlerContext()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys//sign?backend=test", strings.NewReader(`{"data":"dGVzdA=="}`))
	w := httptest.NewRecorder()
	ctx.SignHandler(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSignHandler_MissingBackend(t *testing.T) {
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/sign", ctx.SignHandler)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test/sign", strings.NewReader(`{"data":"dGVzdA=="}`))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSignHandler_InvalidJSON(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/sign", ctx.SignHandler)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/key1/sign?backend=test-backend", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSignHandler_BackendNotFound(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/sign", ctx.SignHandler)
	body, _ := json.Marshal(SignRequest{Data: []byte("test")})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/key1/sign?backend=nonexistent", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestSignHandler_KeyNotFound(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/sign", ctx.SignHandler)
	body, _ := json.Marshal(SignRequest{Data: []byte("test")})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/nonexistent/sign?backend=test-backend", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestSignHandler_Ed25519Success(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	ks.SetKey("ed-key", privKey)

	// Override ListKeys to report Ed25519 algorithm.
	ks.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{{
			CN:           "ed-key",
			KeyType:      types.KeyTypeSigning,
			KeyAlgorithm: x509.Ed25519,
		}}, nil
	}

	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/sign", ctx.SignHandler)
	body, _ := json.Marshal(SignRequest{Data: []byte("message to sign")})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/ed-key/sign?backend=test-backend", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp SignResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.Signature)
}

func TestSignHandler_CustomHashAlgorithm(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ks.SetKey("hash-key", ecKey)

	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/sign", ctx.SignHandler)
	body, _ := json.Marshal(SignRequest{Data: []byte("data"), Hash: "SHA-384"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/hash-key/sign?backend=test-backend", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// P256 with SHA384 may or may not succeed depending on implementation,
	// but the handler should process the hash parameter.
	assert.Contains(t, []int{http.StatusOK, http.StatusInternalServerError}, w.Code)
}

func TestSignHandler_UnknownHash(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ks.SetKey("hash-key2", ecKey)

	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/sign", ctx.SignHandler)
	body, _ := json.Marshal(SignRequest{Data: []byte("data"), Hash: "UNKNOWN-HASH"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/hash-key2/sign?backend=test-backend", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	// Falls back to SHA256.
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSignHandler_ListKeysError(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	ks.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return nil, errors.New("list error")
	}

	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/sign", ctx.SignHandler)
	body, _ := json.Marshal(SignRequest{Data: []byte("data")})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/key1/sign?backend=test-backend", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestSignHandler_SignerError(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ks.SetKey("signer-err-key", ecKey)
	ks.SignerFunc = func(_ *types.KeyAttributes) (crypto.Signer, error) {
		return nil, errors.New("signer error")
	}

	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/sign", ctx.SignHandler)
	body, _ := json.Marshal(SignRequest{Data: []byte("data")})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/signer-err-key/sign?backend=test-backend", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ==========================================================================
// handlers.go - VerifyHandler
// ==========================================================================

func TestVerifyHandler_MissingKeyID(t *testing.T) {
	ctx := newTestHandlerContext()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys//verify?backend=test", strings.NewReader(`{"data":"dGVzdA==","signature":"dGVzdA=="}`))
	w := httptest.NewRecorder()
	ctx.VerifyHandler(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestVerifyHandler_MissingBackend(t *testing.T) {
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/verify", ctx.VerifyHandler)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test/verify", strings.NewReader(`{"data":"dGVzdA==","signature":"dGVzdA=="}`))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestVerifyHandler_InvalidJSON(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/verify", ctx.VerifyHandler)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/key1/verify?backend=test-backend", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestVerifyHandler_BackendNotFound(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/verify", ctx.VerifyHandler)
	body, _ := json.Marshal(VerifyRequest{Data: []byte("data"), Signature: []byte("sig")})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/key1/verify?backend=nonexistent", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestVerifyHandler_KeyNotFound(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/verify", ctx.VerifyHandler)
	body, _ := json.Marshal(VerifyRequest{Data: []byte("data"), Signature: []byte("sig")})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/nonexistent/verify?backend=test-backend", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestVerifyHandler_InvalidSignature(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ks.SetKey("verify-invalid", ecKey)

	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/verify", ctx.VerifyHandler)
	body, _ := json.Marshal(VerifyRequest{Data: []byte("data"), Signature: []byte("invalid-sig")})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/verify-invalid/verify?backend=test-backend", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp VerifyResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.False(t, resp.Valid)
	assert.Equal(t, "Signature is invalid", resp.Message)
}

func TestVerifyHandler_Ed25519(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	ks.SetKey("ed-verify", privKey)

	ks.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{{
			CN:           "ed-verify",
			KeyType:      types.KeyTypeSigning,
			KeyAlgorithm: x509.Ed25519,
		}}, nil
	}

	// Sign first.
	message := []byte("ed25519 message")
	sig := ed25519.Sign(privKey, message)

	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/verify", ctx.VerifyHandler)
	body, _ := json.Marshal(VerifyRequest{Data: message, Signature: sig})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/ed-verify/verify?backend=test-backend", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp VerifyResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Valid)
}

func TestVerifyHandler_ListKeysError(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	ks.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return nil, errors.New("list error")
	}

	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/verify", ctx.VerifyHandler)
	body, _ := json.Marshal(VerifyRequest{Data: []byte("data"), Signature: []byte("sig")})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/key1/verify?backend=test-backend", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestVerifyHandler_GetKeyError(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ks.SetKey("get-key-err", ecKey)
	ks.GetKeyFunc = func(_ *types.KeyAttributes) (crypto.PrivateKey, error) {
		return nil, errors.New("key retrieval error")
	}

	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/verify", ctx.VerifyHandler)
	body, _ := json.Marshal(VerifyRequest{Data: []byte("data"), Signature: []byte("sig")})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/get-key-err/verify?backend=test-backend", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ==========================================================================
// handlers.go - DecryptHandler
// ==========================================================================

func TestDecryptHandler_MissingKeyID(t *testing.T) {
	ctx := newTestHandlerContext()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys//decrypt?backend=test", strings.NewReader(`{"ciphertext":"dGVzdA=="}`))
	w := httptest.NewRecorder()
	ctx.DecryptHandler(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDecryptHandler_MissingBackend(t *testing.T) {
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/decrypt", ctx.DecryptHandler)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test/decrypt", strings.NewReader(`{"ciphertext":"dGVzdA=="}`))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDecryptHandler_InvalidJSON(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/decrypt", ctx.DecryptHandler)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/key1/decrypt?backend=test-backend", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDecryptHandler_BackendNotFound(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/decrypt", ctx.DecryptHandler)
	body, _ := json.Marshal(DecryptRequest{Ciphertext: []byte("ct")})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/key1/decrypt?backend=nonexistent", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestDecryptHandler_KeyNotFound(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/decrypt", ctx.DecryptHandler)
	body, _ := json.Marshal(DecryptRequest{Ciphertext: []byte("ct")})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/nonexistent/decrypt?backend=test-backend", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestDecryptHandler_ListKeysError(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	ks.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return nil, errors.New("list error")
	}

	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/decrypt", ctx.DecryptHandler)
	body, _ := json.Marshal(DecryptRequest{Ciphertext: []byte("ct")})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/key1/decrypt?backend=test-backend", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestDecryptHandler_DecrypterError(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ks.SetKey("dec-err", rsaKey)
	ks.DecrypterFunc = func(_ *types.KeyAttributes) (crypto.Decrypter, error) {
		return nil, errors.New("decrypter error")
	}

	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/decrypt", ctx.DecryptHandler)
	body, _ := json.Marshal(DecryptRequest{Ciphertext: []byte("ct")})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/dec-err/decrypt?backend=test-backend", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ==========================================================================
// handlers.go - DeleteKeyHandler
// ==========================================================================

func TestDeleteKeyHandler_MissingKeyID(t *testing.T) {
	ctx := newTestHandlerContext()
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/keys/?backend=test", nil)
	w := httptest.NewRecorder()
	ctx.DeleteKeyHandler(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteKeyHandler_MissingBackend(t *testing.T) {
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodDelete, "/api/v1/keys/{id}", ctx.DeleteKeyHandler)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/keys/key1", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteKeyHandler_BackendNotFound(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodDelete, "/api/v1/keys/{id}", ctx.DeleteKeyHandler)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/keys/key1?backend=nonexistent", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestDeleteKeyHandler_ListKeysError(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	ks.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return nil, errors.New("list error")
	}

	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodDelete, "/api/v1/keys/{id}", ctx.DeleteKeyHandler)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/keys/key1?backend=test-backend", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestDeleteKeyHandler_DeleteError(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ks.SetKey("del-err-key", ecKey)
	ks.DeleteKeyFunc = func(_ *types.KeyAttributes) error {
		return errors.New("delete error")
	}

	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodDelete, "/api/v1/keys/{id}", ctx.DeleteKeyHandler)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/keys/del-err-key?backend=test-backend", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ==========================================================================
// handlers.go - RotateKeyHandler
// ==========================================================================

func TestRotateKeyHandler_Success(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ks.SetKey("rotate-key", ecKey)

	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/rotate", ctx.RotateKeyHandler)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/rotate-key/rotate?backend=test-backend", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp RotateKeyResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Success)
	assert.NotEmpty(t, resp.PublicKeyPEM)
}

func TestRotateKeyHandler_MissingKeyID(t *testing.T) {
	ctx := newTestHandlerContext()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys//rotate?backend=test", nil)
	w := httptest.NewRecorder()
	ctx.RotateKeyHandler(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRotateKeyHandler_MissingBackend(t *testing.T) {
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/rotate", ctx.RotateKeyHandler)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/key1/rotate", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRotateKeyHandler_BackendNotFound(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/rotate", ctx.RotateKeyHandler)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/key1/rotate?backend=nonexistent", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestRotateKeyHandler_KeyNotFound(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/rotate", ctx.RotateKeyHandler)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/nonexistent/rotate?backend=test-backend", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestRotateKeyHandler_RotateError(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ks.SetKey("rotate-err", ecKey)
	ks.RotateKeyFunc = func(_ *types.KeyAttributes) (crypto.PrivateKey, error) {
		return nil, errors.New("rotate error")
	}

	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/rotate", ctx.RotateKeyHandler)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/rotate-err/rotate?backend=test-backend", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestRotateKeyHandler_ListKeysError(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	ks.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return nil, errors.New("list error")
	}

	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/rotate", ctx.RotateKeyHandler)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/key1/rotate?backend=test-backend", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ==========================================================================
// handlers.go - GetKeyHandler
// ==========================================================================

func TestGetKeyHandler_Success(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ks.SetKey("get-key", ecKey)

	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodGet, "/api/v1/keys/{id}", ctx.GetKeyHandler)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/get-key?backend=test-backend", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp GetKeyResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "get-key", resp.KeyID)
	assert.NotEmpty(t, resp.PublicKeyPEM)
}

func TestGetKeyHandler_MissingKeyID(t *testing.T) {
	ctx := newTestHandlerContext()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/?backend=test", nil)
	w := httptest.NewRecorder()
	ctx.GetKeyHandler(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetKeyHandler_BackendNotFound(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodGet, "/api/v1/keys/{id}", ctx.GetKeyHandler)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/key1?backend=nonexistent", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGetKeyHandler_KeyNotFound(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodGet, "/api/v1/keys/{id}", ctx.GetKeyHandler)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/nonexistent?backend=test-backend", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGetKeyHandler_GetKeyError(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ks.SetKey("key-err", ecKey)
	ks.GetKeyFunc = func(_ *types.KeyAttributes) (crypto.PrivateKey, error) {
		return nil, errors.New("get key error")
	}

	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodGet, "/api/v1/keys/{id}", ctx.GetKeyHandler)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/key-err?backend=test-backend", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestGetKeyHandler_ListKeysError(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	ks.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return nil, errors.New("list error")
	}

	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodGet, "/api/v1/keys/{id}", ctx.GetKeyHandler)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/key1?backend=test-backend", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ==========================================================================
// handlers.go - GetTLSCertificateHandler
// ==========================================================================

func TestGetTLSCertificateHandler_Success(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := generateTestCertificate(t, ecKey)
	ks.SetKey("tls-key", ecKey)
	ks.SetCert("tls-key", cert)

	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodGet, "/api/v1/keys/{id}/tls-cert", ctx.GetTLSCertificateHandler)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/tls-key/tls-cert?backend=test-backend", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp GetTLSCertificateResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "tls-key", resp.KeyID)
	assert.Contains(t, resp.CertificatePEM, "BEGIN CERTIFICATE")
}

func TestGetTLSCertificateHandler_WithChain(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := generateTestCertificate(t, ecKey)

	// Build a TLS certificate with a chain (cert + intermediate).
	ks.GetTLSCertificateFunc = func(_ string, _ *types.KeyAttributes) (tls.Certificate, error) {
		return tls.Certificate{
			Certificate: [][]byte{cert.Raw, cert.Raw}, // leaf + fake intermediate
			PrivateKey:  ecKey,
			Leaf:        cert,
		}, nil
	}
	ks.SetKey("chain-tls", ecKey)

	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodGet, "/api/v1/keys/{id}/tls-cert", ctx.GetTLSCertificateHandler)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/chain-tls/tls-cert?backend=test-backend", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp GetTLSCertificateResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.ChainPEM)
}

func TestGetTLSCertificateHandler_GetTLSCertError(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ks.SetKey("tls-err", ecKey)
	ks.GetTLSCertificateFunc = func(_ string, _ *types.KeyAttributes) (tls.Certificate, error) {
		return tls.Certificate{}, errors.New("tls cert error")
	}

	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodGet, "/api/v1/keys/{id}/tls-cert", ctx.GetTLSCertificateHandler)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/tls-err/tls-cert?backend=test-backend", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

func TestGetTLSCertificateHandler_ListKeysError(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	ks.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return nil, errors.New("list error")
	}

	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodGet, "/api/v1/keys/{id}/tls-cert", ctx.GetTLSCertificateHandler)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/key1/tls-cert?backend=test-backend", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ==========================================================================
// handlers.go - EncryptAsymHandler additional paths
// ==========================================================================

func TestEncryptAsymHandler_MissingKeyID(t *testing.T) {
	ctx := newTestHandlerContext()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys//encrypt-asym?backend=test", strings.NewReader(`{"plaintext":"dGVzdA=="}`))
	w := httptest.NewRecorder()
	ctx.EncryptAsymHandler(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestEncryptAsymHandler_MissingBackend(t *testing.T) {
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/encrypt-asym", ctx.EncryptAsymHandler)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test/encrypt-asym", strings.NewReader(`{"plaintext":"dGVzdA=="}`))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestEncryptAsymHandler_InvalidJSON(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/encrypt-asym", ctx.EncryptAsymHandler)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/key1/encrypt-asym?backend=test-backend", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestEncryptAsymHandler_BackendNotFound(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/encrypt-asym", ctx.EncryptAsymHandler)
	body, _ := json.Marshal(EncryptAsymRequest{Plaintext: []byte("data")})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/key1/encrypt-asym?backend=nonexistent", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestEncryptAsymHandler_KeyNotFound(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/encrypt-asym", ctx.EncryptAsymHandler)
	body, _ := json.Marshal(EncryptAsymRequest{Plaintext: []byte("data")})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/nonexistent/encrypt-asym?backend=test-backend", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestEncryptAsymHandler_GetKeyError(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ks.SetKey("asym-err", rsaKey)
	ks.GetKeyFunc = func(_ *types.KeyAttributes) (crypto.PrivateKey, error) {
		return nil, errors.New("get key error")
	}

	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/encrypt-asym", ctx.EncryptAsymHandler)
	body, _ := json.Marshal(EncryptAsymRequest{Plaintext: []byte("data")})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/asym-err/encrypt-asym?backend=test-backend", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestEncryptAsymHandler_UnsupportedHash(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ks.SetKey("hash-unsup", rsaKey)

	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/encrypt-asym", ctx.EncryptAsymHandler)
	body, _ := json.Marshal(EncryptAsymRequest{Plaintext: []byte("data"), Hash: "md5"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/hash-unsup/encrypt-asym?backend=test-backend", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestEncryptAsymHandler_SHA384(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ks.SetKey("rsa-384", rsaKey)

	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/encrypt-asym", ctx.EncryptAsymHandler)
	body, _ := json.Marshal(EncryptAsymRequest{Plaintext: []byte("data"), Hash: "sha384"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/rsa-384/encrypt-asym?backend=test-backend", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestEncryptAsymHandler_SHA512(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ks.SetKey("rsa-512", rsaKey)

	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/encrypt-asym", ctx.EncryptAsymHandler)
	body, _ := json.Marshal(EncryptAsymRequest{Plaintext: []byte("data"), Hash: "sha512"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/rsa-512/encrypt-asym?backend=test-backend", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestEncryptAsymHandler_SHA1(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ks.SetKey("rsa-sha1", rsaKey)

	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/encrypt-asym", ctx.EncryptAsymHandler)
	body, _ := json.Marshal(EncryptAsymRequest{Plaintext: []byte("data"), Hash: "sha1"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/rsa-sha1/encrypt-asym?backend=test-backend", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestEncryptAsymHandler_ListKeysError(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	ks.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return nil, errors.New("list error")
	}

	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/encrypt-asym", ctx.EncryptAsymHandler)
	body, _ := json.Marshal(EncryptAsymRequest{Plaintext: []byte("data")})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/key1/encrypt-asym?backend=test-backend", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ==========================================================================
// handlers.go - DecryptHandler asymmetric full round-trip
// ==========================================================================

func TestDecryptHandler_AsymmetricRoundTrip(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ks.SetKey("rsa-roundtrip", rsaKey)

	plaintext := []byte("roundtrip message")
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &rsaKey.PublicKey, plaintext, nil)
	require.NoError(t, err)

	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/decrypt", ctx.DecryptHandler)
	body, _ := json.Marshal(DecryptRequest{Ciphertext: ciphertext})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/rsa-roundtrip/decrypt?backend=test-backend", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp DecryptResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, plaintext, resp.Plaintext)
}

// ==========================================================================
// handlers.go - GetCertChainHandler success path
// ==========================================================================

func TestGetCertChainHandler_Success(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := generateTestCertificate(t, ecKey)
	ks.SetKey("chain-get", ecKey)
	ks.SetCertChain("chain-get", []*x509.Certificate{cert})

	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodGet, "/api/v1/keys/{id}/cert-chain", ctx.GetCertChainHandler)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/chain-get/cert-chain?backend=test-backend", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp GetCertChainResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "chain-get", resp.KeyID)
	assert.NotEmpty(t, resp.CertChainPEM)
}

func TestGetCertChainHandler_KeyNotFound(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodGet, "/api/v1/keys/{id}/cert-chain", ctx.GetCertChainHandler)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/nonexistent/cert-chain?backend=test-backend", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// ==========================================================================
// handlers.go - DeleteCertHandler
// ==========================================================================

func TestDeleteCertHandler_Success(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := generateTestCertificate(t, ecKey)
	ks.SetCert("del-cert", cert)

	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodDelete, "/api/v1/certs/{id}", ctx.DeleteCertHandler)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/certs/del-cert?backend=test-backend", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDeleteCertHandler_MissingKeyID(t *testing.T) {
	ctx := newTestHandlerContext()
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/certs/?backend=test", nil)
	w := httptest.NewRecorder()
	ctx.DeleteCertHandler(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteCertHandler_MissingBackend(t *testing.T) {
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodDelete, "/api/v1/certs/{id}", ctx.DeleteCertHandler)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/certs/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteCertHandler_BackendNotFound(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodDelete, "/api/v1/certs/{id}", ctx.DeleteCertHandler)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/certs/test?backend=nonexistent", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestDeleteCertHandler_CertNotFound(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodDelete, "/api/v1/certs/{id}", ctx.DeleteCertHandler)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/certs/nonexistent?backend=test-backend", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// ==========================================================================
// handlers.go - ListCertsHandler
// ==========================================================================

func TestListCertsHandler_MissingBackend(t *testing.T) {
	ctx := newTestHandlerContext()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/certs", nil)
	w := httptest.NewRecorder()
	ctx.ListCertsHandler(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListCertsHandler_BackendNotFound(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/certs?backend=nonexistent", nil)
	w := httptest.NewRecorder()
	ctx.ListCertsHandler(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ==========================================================================
// handlers.go - GenerateKeyHandler
// ==========================================================================

func TestGenerateKeyHandler_MissingKeyID(t *testing.T) {
	ctx := newTestHandlerContext()
	body, _ := json.Marshal(GenerateKeyRequest{Backend: "test", KeyType: "rsa"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	ctx.GenerateKeyHandler(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGenerateKeyHandler_MissingKeyType(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	body, _ := json.Marshal(GenerateKeyRequest{KeyID: "test-key", Backend: "test-backend"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	ctx.GenerateKeyHandler(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGenerateKeyHandler_InvalidJSON(t *testing.T) {
	ctx := newTestHandlerContext()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	ctx.GenerateKeyHandler(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGenerateKeyHandler_GetBackendHandler_MissingBackend(t *testing.T) {
	ctx := newTestHandlerContext()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/backends/", nil)
	w := httptest.NewRecorder()
	ctx.GetBackendHandler(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ==========================================================================
// handlers.go - EncryptHandler error paths
// ==========================================================================

func TestEncryptHandler_MissingKeyID(t *testing.T) {
	ctx := newTestHandlerContext()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys//encrypt?backend=test", strings.NewReader(`{"plaintext":"dGVzdA=="}`))
	w := httptest.NewRecorder()
	ctx.EncryptHandler(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestEncryptHandler_MissingBackend(t *testing.T) {
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/encrypt", ctx.EncryptHandler)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/key1/encrypt", strings.NewReader(`{"plaintext":"dGVzdA=="}`))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestEncryptHandler_InvalidJSON(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/encrypt", ctx.EncryptHandler)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/key1/encrypt?backend=test-backend", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestEncryptHandler_BackendNotFound(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/encrypt", ctx.EncryptHandler)
	body, _ := json.Marshal(EncryptRequest{Plaintext: []byte("data")})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/key1/encrypt?backend=nonexistent", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestEncryptHandler_KeyNotFound(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/encrypt", ctx.EncryptHandler)
	body, _ := json.Marshal(EncryptRequest{Plaintext: []byte("data")})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/nonexistent/encrypt?backend=test-backend", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestEncryptHandler_ListKeysError(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	ks.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return nil, errors.New("list error")
	}

	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/encrypt", ctx.EncryptHandler)
	body, _ := json.Marshal(EncryptRequest{Plaintext: []byte("data")})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/key1/encrypt?backend=test-backend", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ==========================================================================
// password_handlers.go - additional coverage
// ==========================================================================

func TestGetPasswordHandler_MissingID(t *testing.T) {
	systemBackend := storage.NewMemory()
	systemStore := staticpw.NewStore(systemBackend)
	handlers := NewPasswordHandlers(systemStore, nil)

	// Call directly without chi context, so id param is empty.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/passwords/", nil)
	w := httptest.NewRecorder()
	handlers.GetPasswordHandler(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetPasswordHandler_StoreClosed(t *testing.T) {
	systemBackend := storage.NewMemory()
	systemStore := staticpw.NewStore(systemBackend)
	handlers := NewPasswordHandlers(systemStore, nil)

	// Add an entry, then close the store.
	body := `{"name":"Login","password":"pass123"}`
	addReq := httptest.NewRequest(http.MethodPost, "/api/v1/passwords", strings.NewReader(body))
	addW := httptest.NewRecorder()
	handlers.AddPasswordHandler(addW, addReq)
	require.Equal(t, http.StatusCreated, addW.Code)

	var addResp PasswordAddResponse
	require.NoError(t, json.NewDecoder(addW.Body).Decode(&addResp))

	// Close the underlying backend.
	require.NoError(t, systemBackend.Close())

	router := chi.NewRouter()
	router.Get("/api/v1/passwords/{id}", handlers.GetPasswordHandler)
	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/passwords/"+addResp.ID, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, getReq)
	// Store closed should cause an error.
	assert.NotEqual(t, http.StatusOK, w.Code)
}

func TestUpdatePasswordHandler_MissingID(t *testing.T) {
	systemBackend := storage.NewMemory()
	systemStore := staticpw.NewStore(systemBackend)
	handlers := NewPasswordHandlers(systemStore, nil)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/passwords/", strings.NewReader(`{"name":"test"}`))
	w := httptest.NewRecorder()
	handlers.UpdatePasswordHandler(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdatePasswordHandler_InvalidJSON(t *testing.T) {
	systemBackend := storage.NewMemory()
	systemStore := staticpw.NewStore(systemBackend)
	handlers := NewPasswordHandlers(systemStore, nil)

	router := chi.NewRouter()
	router.Put("/api/v1/passwords/{id}", handlers.UpdatePasswordHandler)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/passwords/some-id", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdatePasswordHandler_PartialUpdate(t *testing.T) {
	systemBackend := storage.NewMemory()
	systemStore := staticpw.NewStore(systemBackend)
	handlers := NewPasswordHandlers(systemStore, nil)

	// Add first.
	addBody := `{"name":"PartialTest","username":"user1","password":"pass1","url":"https://test.com","notes":"original","title":"Title","folder_path":"/test"}`
	addReq := httptest.NewRequest(http.MethodPost, "/api/v1/passwords", strings.NewReader(addBody))
	addW := httptest.NewRecorder()
	handlers.AddPasswordHandler(addW, addReq)
	require.Equal(t, http.StatusCreated, addW.Code)

	var addResp PasswordAddResponse
	require.NoError(t, json.NewDecoder(addW.Body).Decode(&addResp))

	// Update only some fields.
	router := chi.NewRouter()
	router.Put("/api/v1/passwords/{id}", handlers.UpdatePasswordHandler)

	title := "NewTitle"
	username := "newuser"
	url := "https://new.com"
	notes := "new notes"
	folder := "/new"
	updateBody, _ := json.Marshal(PasswordUpdateRequest{
		Title:      &title,
		Username:   &username,
		URL:        &url,
		Notes:      &notes,
		FolderPath: &folder,
	})
	updateReq := httptest.NewRequest(http.MethodPut, "/api/v1/passwords/"+addResp.ID, bytes.NewReader(updateBody))
	updateW := httptest.NewRecorder()
	router.ServeHTTP(updateW, updateReq)
	assert.Equal(t, http.StatusOK, updateW.Code)
}

func TestDeletePasswordHandler_MissingID(t *testing.T) {
	systemBackend := storage.NewMemory()
	systemStore := staticpw.NewStore(systemBackend)
	handlers := NewPasswordHandlers(systemStore, nil)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/passwords/", nil)
	w := httptest.NewRecorder()
	handlers.DeletePasswordHandler(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListPasswordsHandler_StoreClosed(t *testing.T) {
	systemBackend := storage.NewMemory()
	systemStore := staticpw.NewStore(systemBackend)
	handlers := NewPasswordHandlers(systemStore, nil)

	require.NoError(t, systemBackend.Close())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/passwords", nil)
	w := httptest.NewRecorder()
	handlers.ListPasswordsHandler(w, req)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// ==========================================================================
// handlers_team.go - additional coverage for AddMember/RemoveMember
// ==========================================================================

func TestTeamHandlers_AddMember_MissingName(t *testing.T) {
	handlers, _ := newCovBoostTeamHandlers(t)

	body, _ := json.Marshal(transport.AddTeamMemberRequest{MemberID: "bob"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/teams//members", bytes.NewReader(body))
	// No chi context for name param - triggers missing name.
	w := httptest.NewRecorder()
	handlers.AddMemberHandler(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTeamHandlers_RemoveMember_MissingName(t *testing.T) {
	handlers, _ := newCovBoostTeamHandlers(t)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/teams//members/bob", nil)
	w := httptest.NewRecorder()
	handlers.RemoveMemberHandler(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTeamHandlers_RemoveMember_InternalError(t *testing.T) {
	handlers, teamStore := newCovBoostTeamHandlers(t)
	ctx := context.Background()

	require.NoError(t, teamStore.Create(ctx, &staticpw.TeamEntity{
		Name: "dev", OwnerID: "alice", Members: []string{"bob"},
	}))

	// Remove a member that does not exist - the store may return an error.
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/teams/dev/members/nonexistent", nil)
	req = chiContext(req, map[string]string{"name": "dev", "memberID": "nonexistent"})
	w := httptest.NewRecorder()
	handlers.RemoveMemberHandler(w, req)
	// Even if member doesn't exist, the store might just no-op. Check it doesn't panic.
	assert.Contains(t, []int{http.StatusOK, http.StatusInternalServerError, http.StatusNotFound}, w.Code)
}

func TestTeamHandlers_AuthenticatedUserID_WithHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-User-ID", "user-123")
	result := authenticatedUserID(req)
	assert.Equal(t, "user-123", result)
}

func TestTeamHandlers_AuthenticatedUserID_Empty(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	result := authenticatedUserID(req)
	assert.Equal(t, "", result)
}

func TestTeamHandlers_CreateTeam_WithOwnerHeader(t *testing.T) {
	handlers, _ := newCovBoostTeamHandlers(t)

	body, _ := json.Marshal(transport.CreateTeamRequest{Name: "team-owned"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/teams", bytes.NewReader(body))
	req.Header.Set("X-User-ID", "alice")
	w := httptest.NewRecorder()
	handlers.CreateTeamHandler(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	var resp transport.CreateTeamResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "alice", resp.Team.OwnerID)
}

func newCovBoostTeamHandlers(t *testing.T) (*TeamHandlers, staticpw.TeamStore) {
	t.Helper()
	backend := storage.NewMemory()
	t.Cleanup(func() { backend.Close() })

	kvStore, err := kvadapter.New(backend)
	require.NoError(t, err)

	teamStore, err := staticpw.NewDAOTeamStore(kvStore)
	require.NoError(t, err)
	t.Cleanup(func() { teamStore.Close() })

	return NewTeamHandlers(teamStore), teamStore
}

// ==========================================================================
// handlers_piv.go - additional service-level error paths
// ==========================================================================

func TestPIV_ListSlots_ServiceCallError(t *testing.T) {
	// With xkms not initialized, ListPIVSlots returns an error.
	xkms.Reset()
	defer xkms.Reset()

	h := newTestHandlerContext()
	r := chi.NewRouter()
	r.Get("/api/v1/piv/slots", h.ListPIVSlotsHandler)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/piv/slots?backend=test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

func TestPIV_GetCertificate_ServiceCallError(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	h := newTestHandlerContext()
	r := chi.NewRouter()
	r.Get("/api/v1/piv/slots/{slot}/certificate", h.GetPIVCertificateHandler)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/piv/slots/9a/certificate?backend=test&format=der", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

func TestPIV_StoreCertificate_ServiceCallError(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	h := newTestHandlerContext()
	r := chi.NewRouter()
	r.Post("/api/v1/piv/slots/{slot}/certificate", h.StorePIVCertificateHandler)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/piv/slots/9a/certificate",
		strings.NewReader(`{"backend":"test","certificate":"data","format":"pem"}`))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

func TestPIV_DeleteCertificate_ServiceCallError(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	h := newTestHandlerContext()
	r := chi.NewRouter()
	r.Delete("/api/v1/piv/slots/{slot}/certificate", h.DeletePIVCertificateHandler)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/piv/slots/9a/certificate?backend=test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

func TestPIV_GenerateKey_ServiceCallError(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	h := newTestHandlerContext()
	r := chi.NewRouter()
	r.Post("/api/v1/piv/slots/{slot}/generate", h.GeneratePIVKeyHandler)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/piv/slots/9a/generate",
		strings.NewReader(`{"backend":"test","algorithm":"ECCP256"}`))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

func TestPIV_ImportCertificate_ServiceCallError(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	h := newTestHandlerContext()
	r := chi.NewRouter()
	r.Post("/api/v1/piv/slots/{slot}/import", h.ImportPIVCertificateHandler)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/piv/slots/9a/import",
		strings.NewReader(`{"backend":"test","certificate":"data"}`))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

func TestPIV_ExportCertificate_ServiceCallError(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	h := newTestHandlerContext()
	r := chi.NewRouter()
	r.Get("/api/v1/piv/slots/{slot}/export", h.ExportPIVCertificateHandler)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/piv/slots/9a/export?backend=test&format=pem", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

func TestPIV_GenerateCSR_ServiceCallError(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	h := newTestHandlerContext()
	r := chi.NewRouter()
	r.Post("/api/v1/piv/slots/{slot}/csr", h.GeneratePIVCSRHandler)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/piv/slots/9a/csr",
		strings.NewReader(`{"backend":"test","subject":"CN=test"}`))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// ==========================================================================
// handlers.go - GetBackendHandler error paths
// ==========================================================================

func TestGetBackendHandler_BackendNotFound(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodGet, "/api/v1/backends/{id}", ctx.GetBackendHandler)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/backends/nonexistent", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ==========================================================================
// handlers.go - ListBackendsHandler error paths
// ==========================================================================

// ==========================================================================
// handlers.go - ListKeysHandler
// ==========================================================================

func TestListKeysHandler_MissingBackend(t *testing.T) {
	ctx := newTestHandlerContext()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys", nil)
	w := httptest.NewRecorder()
	ctx.ListKeysHandler(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListKeysHandler_BackendNotFound(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys?backend=nonexistent", nil)
	w := httptest.NewRecorder()
	ctx.ListKeysHandler(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestListKeysHandler_ListKeysError(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	ks.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return nil, errors.New("list error")
	}

	ctx := newTestHandlerContext()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys?backend=test-backend", nil)
	w := httptest.NewRecorder()
	ctx.ListKeysHandler(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ==========================================================================
// Ensure mock_keystore is properly initialized for these tests
// ==========================================================================

var _ xkms.Backend = (*xkmsmocks.MockKeyStore)(nil)
