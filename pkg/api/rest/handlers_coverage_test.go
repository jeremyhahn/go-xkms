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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- DecryptHandler success path (asymmetric) ---

func TestDecryptHandler_AsymmetricSuccess(t *testing.T) {
	ks := setupTestService(t, "test-backend")

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ks.SetKey("decrypt-key", rsaKey)

	plaintext := []byte("hello world")
	ciphertext, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		&rsaKey.PublicKey,
		plaintext,
		nil,
	)
	require.NoError(t, err)

	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/decrypt", ctx.DecryptHandler)

	body, _ := json.Marshal(DecryptRequest{Ciphertext: ciphertext})
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/keys/decrypt-key/decrypt?backend=test-backend",
		strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp DecryptResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, plaintext, resp.Plaintext)
}

func TestDecryptHandler_DecryptionFailure(t *testing.T) {
	ks := setupTestService(t, "test-backend")

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ks.SetKey("key1", rsaKey)

	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/decrypt", ctx.DecryptHandler)

	body, _ := json.Marshal(DecryptRequest{Ciphertext: []byte("not-valid-ciphertext")})
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/keys/key1/decrypt?backend=test-backend",
		strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.NotEqual(t, http.StatusOK, w.Code)
}

// --- GetCertHandler ---

func TestGetCertHandler_Success(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := generateTestCertificate(t, ecKey)
	ks.SetKey("cert-key", ecKey)
	ks.SetCert("cert-key", cert)

	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodGet, "/api/v1/keys/{id}/cert", ctx.GetCertHandler)
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/keys/cert-key/cert?backend=test-backend", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp GetCertResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "cert-key", resp.KeyID)
	assert.Contains(t, resp.CertificatePEM, "BEGIN CERTIFICATE")
}

func TestGetCertHandler_MissingKeyID(t *testing.T) {
	ctx := newTestHandlerContext()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys//cert?backend=test", nil)
	w := httptest.NewRecorder()
	ctx.GetCertHandler(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetCertHandler_MissingBackend(t *testing.T) {
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodGet, "/api/v1/keys/{id}/cert", ctx.GetCertHandler)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/test/cert", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetCertHandler_CertNotFound(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodGet, "/api/v1/keys/{id}/cert", ctx.GetCertHandler)
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/keys/nonexistent/cert?backend=test-backend", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	// The mock returns an internal error for cert not found (not storage.ErrNotFound).
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// --- CertExistsHandler ---

func TestCertExistsHandler_Exists(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := generateTestCertificate(t, ecKey)
	ks.SetKey("cert-key", ecKey)
	ks.SetCert("cert-key", cert)

	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodHead, "/api/v1/keys/{id}/cert", ctx.CertExistsHandler)
	req := httptest.NewRequest(http.MethodHead,
		"/api/v1/keys/cert-key/cert?backend=test-backend", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCertExistsHandler_NotExists(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodHead, "/api/v1/keys/{id}/cert", ctx.CertExistsHandler)
	req := httptest.NewRequest(http.MethodHead,
		"/api/v1/keys/nonexistent/cert?backend=test-backend", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	// Mock returns key not found which maps to 404.
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestCertExistsHandler_MissingKeyID(t *testing.T) {
	ctx := newTestHandlerContext()
	req := httptest.NewRequest(http.MethodHead, "/api/v1/keys//cert?backend=test", nil)
	w := httptest.NewRecorder()
	ctx.CertExistsHandler(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCertExistsHandler_MissingBackend(t *testing.T) {
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodHead, "/api/v1/keys/{id}/cert", ctx.CertExistsHandler)
	req := httptest.NewRequest(http.MethodHead, "/api/v1/keys/test/cert", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- GetTLSCertificateHandler ---

func TestGetTLSCertificateHandler_MissingKeyID(t *testing.T) {
	ctx := newTestHandlerContext()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys//tls-cert?backend=test", nil)
	w := httptest.NewRecorder()
	ctx.GetTLSCertificateHandler(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetTLSCertificateHandler_MissingBackend(t *testing.T) {
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodGet, "/api/v1/keys/{id}/tls-cert", ctx.GetTLSCertificateHandler)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/test/tls-cert", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetTLSCertificateHandler_BackendNotFound(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodGet, "/api/v1/keys/{id}/tls-cert", ctx.GetTLSCertificateHandler)
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/keys/test/tls-cert?backend=nonexistent", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGetTLSCertificateHandler_KeyNotFound(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodGet, "/api/v1/keys/{id}/tls-cert", ctx.GetTLSCertificateHandler)
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/keys/nonexistent/tls-cert?backend=test-backend", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGetTLSCertificateHandler_NoCert(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ks.SetKey("no-cert", ecKey)

	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodGet, "/api/v1/keys/{id}/tls-cert", ctx.GetTLSCertificateHandler)
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/keys/no-cert/tls-cert?backend=test-backend", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// --- SignHandler ---

func TestSignHandler_Success(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ks.SetKey("sign-key", ecKey)

	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/sign", ctx.SignHandler)

	data := base64.StdEncoding.EncodeToString([]byte("data to sign"))
	body := `{"data":"` + data + `"}`
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/keys/sign-key/sign?backend=test-backend",
		strings.NewReader(body))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp SignResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.Signature)
}

// --- mapErrorToStatusCode ---

func TestMapErrorToStatusCode_AllCases(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{"StorageNotFound", storage.ErrNotFound, http.StatusNotFound},
		{"KeyNotFound", backend.ErrKeyNotFound, http.StatusNotFound},
		{"InvalidRequest", ErrInvalidRequest, http.StatusBadRequest},
		{"InvalidBackend", ErrInvalidBackend, http.StatusBadRequest},
		{"InvalidKeyType", ErrInvalidKeyType, http.StatusBadRequest},
		{"MissingKeyID", ErrMissingKeyID, http.StatusBadRequest},
		{"MissingBackend", ErrMissingBackend, http.StatusBadRequest},
		{"MissingData", ErrMissingData, http.StatusBadRequest},
		{"MissingCiphertext", ErrMissingCiphertext, http.StatusBadRequest},
		{"BackendInvalidKeyType", backend.ErrInvalidKeyType, http.StatusBadRequest},
		{"BackendInvalidKeyPartition", backend.ErrInvalidKeyPartition, http.StatusBadRequest},
		{"SealingNotSupported", ErrSealingNotSupported, http.StatusBadRequest},
		{"AlreadyExists", storage.ErrAlreadyExists, http.StatusConflict},
		{"ServiceUnavailable", ErrServiceUnavailable, http.StatusServiceUnavailable},
		{"Unknown", &mapTestError{"test error"}, http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantStatus, mapErrorToStatusCode(tt.err))
		})
	}
}

type mapTestError struct{ msg string }

func (e *mapTestError) Error() string { return e.msg }

// --- EncryptAsymHandler ---

func TestEncryptAsymHandler_Success(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ks.SetKey("rsa-key", rsaKey)

	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/encrypt-asym", ctx.EncryptAsymHandler)

	body, _ := json.Marshal(EncryptAsymRequest{Plaintext: []byte("secret data")})
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/keys/rsa-key/encrypt-asym?backend=test-backend",
		strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp EncryptAsymResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.Ciphertext)
}

func TestEncryptAsymHandler_NonRSAKey(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ks.SetKey("ec-key", ecKey)

	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/encrypt-asym", ctx.EncryptAsymHandler)

	body, _ := json.Marshal(EncryptAsymRequest{Plaintext: []byte("data")})
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/keys/ec-key/encrypt-asym?backend=test-backend",
		strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// --- SaveCertChainHandler ---

func TestSaveCertChainHandler_Success(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ks.SetKey("chain-key", ecKey)

	cert := generateTestCertificate(t, ecKey)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/cert-chain", ctx.SaveCertChainHandler)

	body, _ := json.Marshal(SaveCertChainRequest{CertChainPEM: []string{string(certPEM)}})
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/keys/chain-key/cert-chain?backend=test-backend",
		strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)
}

// --- DeleteKeyHandler ---

func TestDeleteKeyHandler_Success(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ks.SetKey("del-key", ecKey)

	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodDelete, "/api/v1/keys/{id}", ctx.DeleteKeyHandler)
	req := httptest.NewRequest(http.MethodDelete,
		"/api/v1/keys/del-key?backend=test-backend", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDeleteKeyHandler_NotFound(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodDelete, "/api/v1/keys/{id}", ctx.DeleteKeyHandler)
	req := httptest.NewRequest(http.MethodDelete,
		"/api/v1/keys/nonexistent?backend=test-backend", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- VerifyHandler ---

func TestVerifyHandler_Success(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ks.SetKey("verify-key", ecKey)

	ctx := newTestHandlerContext()
	signRouter := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/sign", ctx.SignHandler)

	signBody, _ := json.Marshal(SignRequest{Data: []byte("data to verify")})
	signReq := httptest.NewRequest(http.MethodPost,
		"/api/v1/keys/verify-key/sign?backend=test-backend",
		strings.NewReader(string(signBody)))
	signW := httptest.NewRecorder()
	signRouter.ServeHTTP(signW, signReq)
	require.Equal(t, http.StatusOK, signW.Code)

	var signResp SignResponse
	require.NoError(t, json.Unmarshal(signW.Body.Bytes(), &signResp))

	verifyRouter := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/verify", ctx.VerifyHandler)
	verifyBody, _ := json.Marshal(VerifyRequest{
		Data:      []byte("data to verify"),
		Signature: signResp.Signature,
	})
	verifyReq := httptest.NewRequest(http.MethodPost,
		"/api/v1/keys/verify-key/verify?backend=test-backend",
		strings.NewReader(string(verifyBody)))
	verifyW := httptest.NewRecorder()
	verifyRouter.ServeHTTP(verifyW, verifyReq)

	assert.Equal(t, http.StatusOK, verifyW.Code)
	var resp VerifyResponse
	require.NoError(t, json.Unmarshal(verifyW.Body.Bytes(), &resp))
	assert.True(t, resp.Valid)
}

// --- GetCertChainHandler ---

func TestGetCertChainHandler_MissingKeyID(t *testing.T) {
	ctx := newTestHandlerContext()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys//cert-chain?backend=test", nil)
	w := httptest.NewRecorder()
	ctx.GetCertChainHandler(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetCertChainHandler_MissingBackend(t *testing.T) {
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodGet, "/api/v1/keys/{id}/cert-chain", ctx.GetCertChainHandler)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/test/cert-chain", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetCertChainHandler_BackendNotFound(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodGet, "/api/v1/keys/{id}/cert-chain", ctx.GetCertChainHandler)
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/keys/test/cert-chain?backend=nonexistent", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}
