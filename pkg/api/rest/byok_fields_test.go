// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-or-later

package rest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/encoding"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestImportKeyHandler_PartitionAndMetadataReachTheBackend proves the two
// fields the REST body used to drop reach the attributes and the wrapped
// material the backend is given.
func TestImportKeyHandler_PartitionAndMetadataReachTheBackend(t *testing.T) {
	ks := setupImportExportTestService(t, "test-backend")
	var attrs *types.KeyAttributes
	var wrapped *backend.WrappedKeyMaterial
	ks.backend.ImportKeyFunc = func(a *types.KeyAttributes, w *backend.WrappedKeyMaterial) error {
		attrs, wrapped = a, w
		return nil
	}
	body := `{"backend":"test-backend","key_id":"k","key_type":"symmetric","aes_key_size":256,"wrapped_key":"` + base64.StdEncoding.EncodeToString([]byte("wrapped")) + `","algorithm":"RSAES_OAEP_SHA_256","partition":"p1","metadata":{"origin":"test"}}`
	w := httptest.NewRecorder()
	newTestHandlerContext().ImportKeyHandler(w, httptest.NewRequest(http.MethodPost, "/api/v1/keys/import", strings.NewReader(body)))
	require.NotNil(t, attrs, "status %d: %s", w.Code, w.Body.String())
	assert.Equal(t, types.Partition("p1"), attrs.Partition)
	assert.Equal(t, map[string]string{"origin": "test"}, wrapped.Metadata)
}

// TestWrapKeyHandler_KeySpecReachesTheBackend proves key_spec reaches the
// import parameters the backend wraps under, and the response carries the
// backend's metadata.
func TestWrapKeyHandler_KeySpecReachesTheBackend(t *testing.T) {
	ks := setupImportExportTestService(t, "test-backend")
	var params *backend.ImportParameters
	ks.backend.WrapKeyFunc = func(_ []byte, p *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
		params = p
		return &backend.WrappedKeyMaterial{WrappedKey: []byte("w"), Algorithm: p.Algorithm, Metadata: map[string]string{"k": "v"}}, nil
	}
	pemKey, err := encoding.EncodePublicKeyPEM(&ks.backend.wrappingKey.PublicKey)
	require.NoError(t, err)
	body := map[string]any{"backend": "test-backend", "key_material": base64.StdEncoding.EncodeToString([]byte("material")), "wrapping_public_key_pem": string(pemKey), "algorithm": "RSAES_OAEP_SHA_256", "key_spec": "RSA_2048"}
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	w := httptest.NewRecorder()
	newTestHandlerContext().WrapKeyHandler(w, httptest.NewRequest(http.MethodPost, "/api/v1/keys/wrap", strings.NewReader(string(raw))))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.NotNil(t, params)
	assert.Equal(t, "RSA_2048", params.KeySpec)
	var resp WrapKeyResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, map[string]string{"k": "v"}, resp.Metadata)
}

// TestGetImportParametersHandler_ReportsTheKeySpec proves the backend's key
// spec reaches the response so a caller can carry it into the wrap.
func TestGetImportParametersHandler_ReportsTheKeySpec(t *testing.T) {
	setupImportExportTestService(t, "test-backend")
	body := `{"backend": "test-backend", "key_id": "k", "key_type": "rsa", "algorithm": "RSAES_OAEP_SHA_256"}`
	w := httptest.NewRecorder()
	newTestHandlerContext().GetImportParametersHandler(w, httptest.NewRequest(http.MethodPost, "/api/v1/keys/import-params", strings.NewReader(body)))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp GetImportParametersResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "RSA_2048", resp.KeySpec)
}

// TestGenerateKeyHandler_PartitionReachesTheBackend proves the partition the
// REST generate body used to drop reaches the attributes the backend stores
// the key under; it is part of the key's identity on every other transport.
func TestGenerateKeyHandler_PartitionReachesTheBackend(t *testing.T) {
	ks := setupTestService(t, "test-backend")
	var partition types.Partition
	ks.GenerateRSAFunc = func(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
		partition = attrs.Partition
		return rsa.GenerateKey(rand.Reader, 2048)
	}
	body := `{"backend":"test-backend","key_id":"k","key_type":"rsa","algorithm":"rsa","partition":"p1"}`
	w := httptest.NewRecorder()
	newTestHandlerContext().GenerateKeyHandler(w, httptest.NewRequest(http.MethodPost, "/api/v1/keys", strings.NewReader(body)))
	require.Less(t, w.Code, 300, w.Body.String())
	assert.Equal(t, types.Partition("p1"), partition)
}
