// Copyright (c) 2025 Jeremy Hahn
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

// restImportCapturingAttrs drives ImportKeyHandler with the given body and
// returns the attributes the backend was asked to store.
func restImportCapturingAttrs(t *testing.T, body map[string]any) (*types.KeyAttributes, int) {
	t.Helper()
	ks := setupImportExportTestService(t, "test-backend")
	var captured *types.KeyAttributes
	ks.backend.ImportKeyFunc = func(attrs *types.KeyAttributes, _ *backend.WrappedKeyMaterial) error {
		captured = attrs
		return nil
	}
	ctx := newTestHandlerContext()

	body["backend"] = "test-backend"
	body["wrapped_key"] = base64.StdEncoding.EncodeToString([]byte("wrapped"))
	body["algorithm"] = "RSAES_OAEP_SHA_256"
	raw, err := json.Marshal(body)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import", strings.NewReader(string(raw)))
	w := httptest.NewRecorder()
	ctx.ImportKeyHandler(w, req)
	require.NotNil(t, captured, "the import must reach the backend: status %d body %s", w.Code, w.Body.String())
	return captured, w.Code
}

// TestImportKeyHandler_Exportability proves the REST import carries the
// caller's exportability choice to the backend, and that a request saying
// nothing gets the same write-once default the other transports apply: a
// symmetric key exportable, an asymmetric one not. This path used to set
// nothing, so every symmetric key imported over REST was stored
// non-exportable.
func TestImportKeyHandler_Exportability(t *testing.T) {
	t.Run("symmetric default is exportable", func(t *testing.T) {
		attrs, code := restImportCapturingAttrs(t, map[string]any{"key_id": "aes-default", "key_type": "symmetric", "aes_key_size": 256})
		assert.Less(t, code, 300)
		assert.True(t, attrs.Exportable)
		assert.False(t, attrs.Sensitive)
	})
	t.Run("symmetric explicit false is honoured", func(t *testing.T) {
		attrs, code := restImportCapturingAttrs(t, map[string]any{"key_id": "aes-locked", "key_type": "symmetric", "aes_key_size": 256, "exportable": false, "sensitive": true})
		assert.Less(t, code, 300)
		assert.False(t, attrs.Exportable)
		assert.True(t, attrs.Sensitive)
	})
	t.Run("asymmetric default is not exportable", func(t *testing.T) {
		attrs, _ := restImportCapturingAttrs(t, map[string]any{"key_id": "rsa-default", "key_type": "rsa", "key_size": 2048})
		assert.False(t, attrs.Exportable)
	})
	t.Run("asymmetric explicit true is honoured", func(t *testing.T) {
		attrs, _ := restImportCapturingAttrs(t, map[string]any{"key_id": "rsa-open", "key_type": "rsa", "key_size": 2048, "exportable": true})
		assert.True(t, attrs.Exportable)
	})
}
