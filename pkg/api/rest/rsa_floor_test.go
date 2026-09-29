// Copyright (c) 2026 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-or-later

package rest

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestGenerateKeyHandler_RSAFloor proves that a REST caller asking for an
// RSA key below the 2048-bit floor (go-xkms#1204) is refused by the service
// layer's own validation rather than reaching the backend. GenerateKeyHandler
// now calls XKMSService.GenerateKey directly (go-xkms#1214), so this is the
// service's floor, not a copy kept in this transport.
func TestGenerateKeyHandler_RSAFloor(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()

	body := `{"key_id": "rsa-1024", "backend": "test-backend", "key_type": "rsa", "algorithm": "rsa", "key_size": 1024}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", strings.NewReader(body))
	w := httptest.NewRecorder()

	ctx.GenerateKeyHandler(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "2048")
}

// TestImportKeyHandler_RSAFloor proves the REST import ceremony refuses an
// RSA-1024 import with the same floor GenerateKeyHandler enforces. Before
// go-xkms#1214 this path built its key attributes without ever calling
// types.KeyAttributes.Validate, so an undersized RSA import reached the
// backend unchecked.
func TestImportKeyHandler_RSAFloor(t *testing.T) {
	ks := setupImportExportTestService(t, "test-backend")
	imported := false
	ks.backend.ImportKeyFunc = func(_ *types.KeyAttributes, _ *backend.WrappedKeyMaterial) error {
		imported = true
		return nil
	}
	ctx := newTestHandlerContext()

	body := `{"backend":"test-backend","key_id":"rsa-1024-import","key_type":"rsa","key_size":1024,"wrapped_key":"` +
		base64.StdEncoding.EncodeToString([]byte("wrapped")) + `","algorithm":"RSAES_OAEP_SHA_256"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import", strings.NewReader(body))
	w := httptest.NewRecorder()

	ctx.ImportKeyHandler(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "2048")
	assert.False(t, imported, "the undersized key must never reach the backend's ImportKey")
}

// TestGetImportParametersHandler_RSAFloor proves the import-parameter
// negotiation step refuses an RSA-1024 request rather than handing back
// working wrapping parameters for a key ImportKey will refuse anyway.
func TestGetImportParametersHandler_RSAFloor(t *testing.T) {
	setupImportExportTestService(t, "test-backend")
	ctx := newTestHandlerContext()

	body := `{"backend": "test-backend", "key_id": "rsa-1024-params", "key_type": "rsa", "key_size": 1024, "algorithm": "RSAES_OAEP_SHA_256"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import-params", strings.NewReader(body))
	w := httptest.NewRecorder()

	ctx.GetImportParametersHandler(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "2048")
}

// TestGenerateKeyHandler_InvalidAttributesRefused proves that a request the
// service layer's own attribute validation refuses -- an ECDSA request
// naming no recognisable curve -- comes back as 400 through the service
// path, not a 500. See TestGenerateKeyHandler_UnknownCurve for the
// curve-name-in-response assertion this complements.
func TestGenerateKeyHandler_InvalidAttributesRefused(t *testing.T) {
	setupTestService(t, "test-backend")
	ctx := newTestHandlerContext()

	body, err := json.Marshal(GenerateKeyRequest{
		KeyID:   "bad-attrs",
		Backend: "test-backend",
		KeyType: "signing",
		// No algorithm recognised as either symmetric or asymmetric.
		Algorithm: "quantum-resistant-mystery-cipher",
	})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", strings.NewReader(string(body)))
	w := httptest.NewRecorder()

	ctx.GenerateKeyHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
}
