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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

const otaTestBoard = "stm32-h7"

// otaImageRouter routes the three OTA image-key handlers as routes.go does.
func otaImageRouter(h *HandlerContext) http.Handler {
	r := chi.NewRouter()
	r.Post("/api/v1/ota-image-keys/{board}", h.CreateOTAImageKeyHandler)
	r.Post("/api/v1/ota-image-keys/{board}/rotate", h.RotateOTAImageKeyHandler)
	r.Post("/api/v1/ota-image-keys/{board}/sign", h.SignOTAImageHandler)
	return r
}

// serveOTA sends body to path as tenant A and returns the recorded response.
func serveOTA(t *testing.T, router http.Handler, path string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	router.ServeHTTP(w, tenantIdentityRequest(t, http.MethodPost, path, body, crossTenantA))
	return w
}

// otaPublicKey parses an ECDSA public key from a response's PEM.
func otaPublicKey(t *testing.T, pemText string) *ecdsa.PublicKey {
	t.Helper()
	block, _ := pem.Decode([]byte(pemText))
	require.NotNil(t, block, "response carries no public key PEM")
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	ec, ok := pub.(*ecdsa.PublicKey)
	require.True(t, ok, "public key is %T, not ECDSA", pub)
	return ec
}

// verifyOTASignature checks an ES256 OTA_AUTH signature in the RFC 9053
// §2.1 encoding: 32-byte big-endian r, then 32-byte big-endian s.
func verifyOTASignature(t *testing.T, pub *ecdsa.PublicKey, digest, sig []byte) bool {
	t.Helper()
	require.Len(t, sig, 64, "an ES256 OTA signature is r || s, 64 bytes")
	return ecdsa.Verify(pub, digest, new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
}

func TestOTAImageKeyHandlers_CreateRotateSign(t *testing.T) {
	h, _ := crossTenantHandlerContext(t)
	router := otaImageRouter(h)
	base := "/api/v1/ota-image-keys/" + otaTestBoard

	w := serveOTA(t, router, base, OTAImageKeyRequest{Backend: crossTenantSource, Algorithm: "ES256"})
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var created GenerateKeyResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &created))
	assert.Equal(t, "ota-image-"+otaTestBoard, created.KeyID)
	assert.Equal(t, elliptic.P256(), otaPublicKey(t, created.PublicKeyPEM).Curve)

	w = serveOTA(t, router, base+"/rotate", OTAImageKeyRequest{Backend: crossTenantSource})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var rotated RotateKeyResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &rotated))
	assert.Equal(t, uint32(2), rotated.KeyVersion)

	digest := sha256.Sum256([]byte("firmware image"))
	w = serveOTA(t, router, base+"/sign", OTAImageSignRequest{
		Backend: crossTenantSource, Data: digest[:], DataIsDigest: true,
	})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var signed SignResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &signed))
	assert.Equal(t, uint32(2), signed.KeyVersion, "signs with the current version")
	assert.True(t, verifyOTASignature(t, otaPublicKey(t, rotated.PublicKeyPEM), digest[:], signed.Signature),
		"signature does not verify under the rotated key")
}

func TestOTAImageKeyHandlers_InvalidArgument(t *testing.T) {
	h, svc := crossTenantHandlerContext(t)
	router := otaImageRouter(h)

	// A key created outside the OTA path under a board's key ID, on P-384.
	scoped, err := svc.LookupTenantBackend(crossTenantSource, crossTenantA)
	require.NoError(t, err)
	_, err = scoped.GenerateECDSA(context.Background(), &types.KeyAttributes{
		CN:            "ota-image-p384-board",
		KeyType:       types.KeyTypeSigning,
		StoreType:     types.StoreSoftware,
		KeyAlgorithm:  x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P384()},
	})
	require.NoError(t, err)

	keyReq := OTAImageKeyRequest{Backend: crossTenantSource}
	signReq := OTAImageSignRequest{Backend: crossTenantSource, Data: []byte("image")}
	tests := []struct {
		name string
		path string
		body interface{}
	}{
		{"create malformed board id", "/api/v1/ota-image-keys/Bad--Board", keyReq},
		{"create non-ES256 algorithm", "/api/v1/ota-image-keys/" + otaTestBoard, OTAImageKeyRequest{Backend: crossTenantSource, Algorithm: "RS256"}},
		{"create missing backend", "/api/v1/ota-image-keys/" + otaTestBoard, OTAImageKeyRequest{}},
		{"rotate malformed board id", "/api/v1/ota-image-keys/bad--board/rotate", keyReq},
		{"rotate non-ES256 algorithm", "/api/v1/ota-image-keys/" + otaTestBoard + "/rotate", OTAImageKeyRequest{Backend: crossTenantSource, Algorithm: "PS256"}},
		{"rotate non-ES256 key", "/api/v1/ota-image-keys/p384-board/rotate", keyReq},
		{"sign malformed board id", "/api/v1/ota-image-keys/-board/sign", signReq},
		{"sign non-ES256 key", "/api/v1/ota-image-keys/p384-board/sign", signReq},
		{"sign missing backend", "/api/v1/ota-image-keys/" + otaTestBoard + "/sign", OTAImageSignRequest{Data: []byte("image")}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := serveOTA(t, router, tc.path, tc.body)
			assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
		})
	}
}

func TestOTAImageKeyHandlers_MalformedBody(t *testing.T) {
	h, _ := crossTenantHandlerContext(t)
	router := otaImageRouter(h)

	for _, suffix := range []string{"", "/rotate", "/sign"} {
		t.Run("path"+suffix, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/v1/ota-image-keys/"+otaTestBoard+suffix,
				bytes.NewBufferString("{not json"))
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
		})
	}
}

func TestOTAImageKeyHandlers_UnknownBoardKey(t *testing.T) {
	h, _ := crossTenantHandlerContext(t)
	router := otaImageRouter(h)

	w := serveOTA(t, router, "/api/v1/ota-image-keys/"+otaTestBoard+"/rotate",
		OTAImageKeyRequest{Backend: crossTenantSource})
	assert.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
}
