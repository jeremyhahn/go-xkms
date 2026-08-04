// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package rest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBackendFromRequest covers the query-wins / body-fallback / both-empty
// resolution logic directly.
func TestBackendFromRequest(t *testing.T) {
	t.Run("query wins over body", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/x?backend=from-query", nil)
		assert.Equal(t, "from-query", backendFromRequest(r, "from-body"))
	})
	t.Run("body used when query absent", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/x", nil)
		assert.Equal(t, "from-body", backendFromRequest(r, "from-body"))
	})
	t.Run("empty when neither present", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/x", nil)
		assert.Equal(t, "", backendFromRequest(r, ""))
	})
	t.Run("empty query falls back to body", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/x?backend=", nil)
		assert.Equal(t, "from-body", backendFromRequest(r, "from-body"))
	})
}

// TestSignHandler_BackendFromBody is the direct regression for the reported
// inconsistency: the crypto handlers historically required the backend as a URL
// query parameter and ignored the body "backend" field the DTO advertises,
// 400-ing clients that followed the DTO. It must now succeed with the backend
// supplied ONLY in the body (no query parameter).
func TestSignHandler_BackendFromBody(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ks.SetKey("body-backend-sign-key", ecKey)

	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/sign", ctx.SignHandler)

	data := base64.StdEncoding.EncodeToString([]byte("data to sign"))
	// Backend in the BODY only — NO ?backend= query parameter.
	body := `{"backend":"test-backend","data":"` + data + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/body-backend-sign-key/sign",
		strings.NewReader(body))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equalf(t, http.StatusOK, w.Code, "body-only backend must be accepted; got %d: %s", w.Code, w.Body.String())
	var resp SignResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.Signature)
}

// TestSignHandler_MissingBackendBothEmpty confirms the 400 is preserved when the
// backend is absent from BOTH the query and the body.
func TestSignHandler_MissingBackendBothEmpty(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ks.SetKey("no-backend-key", ecKey)

	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/sign", ctx.SignHandler)

	data := base64.StdEncoding.EncodeToString([]byte("data"))
	body := `{"data":"` + data + `"}` // no backend anywhere
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/no-backend-key/sign",
		strings.NewReader(body))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestVerifyHandler_BackendFromBody proves the body-backend path on Verify:
// sign with the query (known-good), then verify supplying the backend only in
// the body.
func TestVerifyHandler_BackendFromBody(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ks.SetKey("body-backend-verify-key", ecKey)

	ctx := newTestHandlerContext()
	signRouter := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/sign", ctx.SignHandler)
	verifyRouter := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/verify", ctx.VerifyHandler)

	rawData := []byte("verify-me")
	data := base64.StdEncoding.EncodeToString(rawData)

	// Sign via the query parameter.
	signReq := httptest.NewRequest(http.MethodPost,
		"/api/v1/keys/body-backend-verify-key/sign?backend=test-backend",
		strings.NewReader(`{"data":"`+data+`"}`))
	signW := httptest.NewRecorder()
	signRouter.ServeHTTP(signW, signReq)
	require.Equal(t, http.StatusOK, signW.Code, signW.Body.String())
	var signResp SignResponse
	require.NoError(t, json.Unmarshal(signW.Body.Bytes(), &signResp))

	// Verify with the backend supplied ONLY in the body.
	sigB64 := base64.StdEncoding.EncodeToString(signResp.Signature)
	verifyBody := `{"backend":"test-backend","data":"` + data + `","signature":"` + sigB64 + `"}`
	verifyReq := httptest.NewRequest(http.MethodPost,
		"/api/v1/keys/body-backend-verify-key/verify",
		strings.NewReader(verifyBody))
	verifyW := httptest.NewRecorder()
	verifyRouter.ServeHTTP(verifyW, verifyReq)

	require.Equalf(t, http.StatusOK, verifyW.Code, "body-only backend must be accepted on verify; got %d: %s", verifyW.Code, verifyW.Body.String())
	var verifyResp VerifyResponse
	require.NoError(t, json.Unmarshal(verifyW.Body.Bytes(), &verifyResp))
	assert.True(t, verifyResp.Valid, "signature should verify")
}
