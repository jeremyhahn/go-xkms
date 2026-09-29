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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTwoImportExportBackends registers two independent import/export capable
// backends under the given names and returns them in registration order. Both
// are equally eligible for wrap/unwrap, so a handler that scans the backend map
// instead of honoring the caller's choice picks one at random.
func setupTwoImportExportBackends(t *testing.T, first, second string) (*mockKeyStoreWithImportExport, *mockKeyStoreWithImportExport) {
	t.Helper()

	firstKS := newMockKeyStoreWithImportExport()
	secondKS := newMockKeyStoreWithImportExport()

	xkms.Reset()
	err := xkms.Initialize(&xkms.ServiceConfig{
		Backends: map[string]xkms.Backend{
			first:  firstKS,
			second: secondKS,
		},
		DefaultBackend: first,
	})
	require.NoError(t, err)
	t.Cleanup(xkms.Reset)

	return firstKS, secondKS
}

// countingWrap installs a WrapKey stub that records invocations and returns a
// backend-identifying marker so the response proves which backend ran.
func countingWrap(ks *mockKeyStoreWithImportExport, marker string, calls *atomic.Int64) {
	ks.backend.WrapKeyFunc = func(keyMaterial []byte, params *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
		calls.Add(1)
		return &backend.WrappedKeyMaterial{
			WrappedKey:  []byte(marker),
			Algorithm:   params.Algorithm,
			ImportToken: params.ImportToken,
		}, nil
	}
}

// countingUnwrap installs an UnwrapKey stub that records invocations and
// returns a backend-identifying marker.
func countingUnwrap(ks *mockKeyStoreWithImportExport, marker string, calls *atomic.Int64) {
	ks.backend.UnwrapKeyFunc = func(wrapped *backend.WrappedKeyMaterial, params *backend.ImportParameters) ([]byte, error) {
		calls.Add(1)
		return []byte(marker), nil
	}
}

func wrapRequestBody(t *testing.T, backendName, wrappingKeyPEM string) string {
	t.Helper()
	return fmt.Sprintf(`{"backend": %q, "key_material": "dGVzdCBrZXkgbWF0ZXJpYWw=", "wrapping_public_key_pem": %q, "algorithm": "RSAES_OAEP_SHA_256"}`,
		backendName, wrappingKeyPEM)
}

func unwrapRequestBody(t *testing.T, backendName, wrappingKeyPEM, wrappedB64 string) string {
	t.Helper()
	return fmt.Sprintf(`{"backend": %q, "wrapped_key": %q, "wrapping_public_key_pem": %q, "algorithm": "RSAES_OAEP_SHA_256"}`,
		backendName, wrappedB64, wrappingKeyPEM)
}

func doWrap(ctx *HandlerContext, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/wrap", strings.NewReader(body))
	w := httptest.NewRecorder()
	ctx.WrapKeyHandler(w, req)
	return w
}

func doUnwrap(ctx *HandlerContext, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/unwrap", strings.NewReader(body))
	w := httptest.NewRecorder()
	ctx.UnwrapKeyHandler(w, req)
	return w
}

// ============================================================================
// The named backend is honored
// ============================================================================

func TestWrapKeyHandler_UsesNamedBackend(t *testing.T) {
	t.Run("wraps with the backend named in the request", func(t *testing.T) {
		alpha, beta := setupTwoImportExportBackends(t, "alpha", "beta")
		ctx := newTestHandlerContext()

		var alphaCalls, betaCalls atomic.Int64
		countingWrap(alpha, "wrapped-by-alpha", &alphaCalls)
		countingWrap(beta, "wrapped-by-beta", &betaCalls)

		pem := getWrappingPublicKeyPEM(t, beta.backend.wrappingKey)
		w := doWrap(ctx, wrapRequestBody(t, "beta", pem))

		require.Equal(t, http.StatusOK, w.Code)

		var resp WrapKeyResponse
		require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
		assert.Equal(t, "wrapped-by-beta", string(resp.WrappedKey))
		assert.Equal(t, int64(1), betaCalls.Load())
		assert.Equal(t, int64(0), alphaCalls.Load(), "the unnamed backend must never be invoked")
	})

	t.Run("propagates the named backend's failure instead of trying another", func(t *testing.T) {
		alpha, beta := setupTwoImportExportBackends(t, "alpha", "beta")
		ctx := newTestHandlerContext()

		var betaCalls atomic.Int64
		countingWrap(beta, "wrapped-by-beta", &betaCalls)
		alpha.backend.WrapKeyFunc = func(keyMaterial []byte, params *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
			return nil, &errs.Message{Msg: "alpha cannot wrap"}
		}

		pem := getWrappingPublicKeyPEM(t, alpha.backend.wrappingKey)
		w := doWrap(ctx, wrapRequestBody(t, "alpha", pem))

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Equal(t, int64(0), betaCalls.Load(), "a failing named backend must not fall back to another backend")
	})
}

func TestUnwrapKeyHandler_UsesNamedBackend(t *testing.T) {
	t.Run("unwraps with the backend named in the request", func(t *testing.T) {
		alpha, beta := setupTwoImportExportBackends(t, "alpha", "beta")
		ctx := newTestHandlerContext()

		var alphaCalls, betaCalls atomic.Int64
		countingUnwrap(alpha, "unwrapped-by-alpha", &alphaCalls)
		countingUnwrap(beta, "unwrapped-by-beta", &betaCalls)

		pem := getWrappingPublicKeyPEM(t, beta.backend.wrappingKey)
		w := doUnwrap(ctx, unwrapRequestBody(t, "beta", pem, base64.StdEncoding.EncodeToString([]byte("ciphertext"))))

		require.Equal(t, http.StatusOK, w.Code)

		var resp UnwrapKeyResponse
		require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
		assert.Equal(t, "unwrapped-by-beta", string(resp.KeyMaterial))
		assert.Equal(t, int64(1), betaCalls.Load())
		assert.Equal(t, int64(0), alphaCalls.Load(), "the unnamed backend must never be invoked")
	})

	t.Run("propagates the named backend's failure instead of trying another", func(t *testing.T) {
		alpha, beta := setupTwoImportExportBackends(t, "alpha", "beta")
		ctx := newTestHandlerContext()

		var betaCalls atomic.Int64
		countingUnwrap(beta, "unwrapped-by-beta", &betaCalls)
		alpha.backend.UnwrapKeyFunc = func(wrapped *backend.WrappedKeyMaterial, params *backend.ImportParameters) ([]byte, error) {
			return nil, &errs.Message{Msg: "alpha cannot unwrap"}
		}

		pem := getWrappingPublicKeyPEM(t, alpha.backend.wrappingKey)
		w := doUnwrap(ctx, unwrapRequestBody(t, "alpha", pem, base64.StdEncoding.EncodeToString([]byte("ciphertext"))))

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Equal(t, int64(0), betaCalls.Load(), "a failing named backend must not fall back to another backend")
	})
}

// ============================================================================
// Regression: the arbitrary first-match backend scan is gone
// ============================================================================

// TestWrapUnwrapKeyHandler_NoArbitraryBackendSelection pins the defect that
// wrap/unwrap used to iterate the backend map and take the first backend that
// implemented ImportExportBackend. Go randomizes map iteration order, so the
// old code served roughly half of these requests from the wrong backend; the
// repetition makes that failure certain rather than flaky.
func TestWrapUnwrapKeyHandler_NoArbitraryBackendSelection(t *testing.T) {
	const iterations = 25

	t.Run("wrap always uses the requested backend, never the other one", func(t *testing.T) {
		alpha, beta := setupTwoImportExportBackends(t, "alpha", "beta")
		ctx := newTestHandlerContext()

		var alphaCalls, betaCalls atomic.Int64
		countingWrap(alpha, "wrapped-by-alpha", &alphaCalls)
		countingWrap(beta, "wrapped-by-beta", &betaCalls)

		pem := getWrappingPublicKeyPEM(t, beta.backend.wrappingKey)
		for i := 0; i < iterations; i++ {
			w := doWrap(ctx, wrapRequestBody(t, "beta", pem))
			require.Equal(t, http.StatusOK, w.Code)

			var resp WrapKeyResponse
			require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
			require.Equal(t, "wrapped-by-beta", string(resp.WrappedKey))
		}

		assert.Equal(t, int64(iterations), betaCalls.Load())
		assert.Equal(t, int64(0), alphaCalls.Load(), "backend selection must not depend on map iteration order")
	})

	t.Run("unwrap always uses the requested backend, never the other one", func(t *testing.T) {
		alpha, beta := setupTwoImportExportBackends(t, "alpha", "beta")
		ctx := newTestHandlerContext()

		var alphaCalls, betaCalls atomic.Int64
		countingUnwrap(alpha, "unwrapped-by-alpha", &alphaCalls)
		countingUnwrap(beta, "unwrapped-by-beta", &betaCalls)

		pem := getWrappingPublicKeyPEM(t, beta.backend.wrappingKey)
		wrappedB64 := base64.StdEncoding.EncodeToString([]byte("ciphertext"))
		for i := 0; i < iterations; i++ {
			w := doUnwrap(ctx, unwrapRequestBody(t, "beta", pem, wrappedB64))
			require.Equal(t, http.StatusOK, w.Code)

			var resp UnwrapKeyResponse
			require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
			require.Equal(t, "unwrapped-by-beta", string(resp.KeyMaterial))
		}

		assert.Equal(t, int64(iterations), betaCalls.Load())
		assert.Equal(t, int64(0), alphaCalls.Load(), "backend selection must not depend on map iteration order")
	})
}

// ============================================================================
// Round trip through one named backend
// ============================================================================

func TestWrapUnwrapKeyHandler_RoundTripThroughSameBackend(t *testing.T) {
	t.Run("material wrapped by a backend is recovered by the same backend", func(t *testing.T) {
		_, beta := setupTwoImportExportBackends(t, "alpha", "beta")
		ctx := newTestHandlerContext()

		pem := getWrappingPublicKeyPEM(t, beta.backend.wrappingKey)
		plaintext := []byte("test key material")

		wrapW := doWrap(ctx, fmt.Sprintf(
			`{"backend": "beta", "key_material": %q, "wrapping_public_key_pem": %q, "algorithm": "RSAES_OAEP_SHA_256"}`,
			base64.StdEncoding.EncodeToString(plaintext), pem))
		require.Equal(t, http.StatusOK, wrapW.Code)

		var wrapResp WrapKeyResponse
		require.NoError(t, json.NewDecoder(wrapW.Body).Decode(&wrapResp))
		require.NotEmpty(t, wrapResp.WrappedKey)

		unwrapW := doUnwrap(ctx, unwrapRequestBody(t, "beta", pem,
			base64.StdEncoding.EncodeToString(wrapResp.WrappedKey)))
		require.Equal(t, http.StatusOK, unwrapW.Code)

		var unwrapResp UnwrapKeyResponse
		require.NoError(t, json.NewDecoder(unwrapW.Body).Decode(&unwrapResp))
		assert.Equal(t, plaintext, []byte(unwrapResp.KeyMaterial))
	})
}

// ============================================================================
// Backend resolution errors
// ============================================================================

func TestWrapUnwrapKeyHandler_BackendResolutionErrors(t *testing.T) {
	t.Run("missing backend is rejected with 400", func(t *testing.T) {
		_, beta := setupTwoImportExportBackends(t, "alpha", "beta")
		ctx := newTestHandlerContext()
		pem := getWrappingPublicKeyPEM(t, beta.backend.wrappingKey)

		wrapW := doWrap(ctx, wrapRequestBody(t, "", pem))
		assert.Equal(t, http.StatusBadRequest, wrapW.Code)
		assert.Contains(t, wrapW.Body.String(), ErrMissingBackend.Error())

		unwrapW := doUnwrap(ctx, unwrapRequestBody(t, "", pem, base64.StdEncoding.EncodeToString([]byte("ct"))))
		assert.Equal(t, http.StatusBadRequest, unwrapW.Code)
		assert.Contains(t, unwrapW.Body.String(), ErrMissingBackend.Error())
	})

	t.Run("omitting the backend never falls back to an arbitrary backend", func(t *testing.T) {
		alpha, beta := setupTwoImportExportBackends(t, "alpha", "beta")
		ctx := newTestHandlerContext()

		var alphaCalls, betaCalls atomic.Int64
		countingWrap(alpha, "wrapped-by-alpha", &alphaCalls)
		countingWrap(beta, "wrapped-by-beta", &betaCalls)

		pem := getWrappingPublicKeyPEM(t, beta.backend.wrappingKey)
		w := doWrap(ctx, wrapRequestBody(t, "", pem))

		require.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, int64(0), alphaCalls.Load())
		assert.Equal(t, int64(0), betaCalls.Load())
	})

	t.Run("unknown backend is rejected with 404", func(t *testing.T) {
		_, beta := setupTwoImportExportBackends(t, "alpha", "beta")
		ctx := newTestHandlerContext()
		pem := getWrappingPublicKeyPEM(t, beta.backend.wrappingKey)

		wrapW := doWrap(ctx, wrapRequestBody(t, "does-not-exist", pem))
		assert.Equal(t, http.StatusNotFound, wrapW.Code)
		assert.Contains(t, wrapW.Body.String(), ErrBackendNotFound.Error())

		unwrapW := doUnwrap(ctx, unwrapRequestBody(t, "does-not-exist", pem, base64.StdEncoding.EncodeToString([]byte("ct"))))
		assert.Equal(t, http.StatusNotFound, unwrapW.Code)
		assert.Contains(t, unwrapW.Body.String(), ErrBackendNotFound.Error())
	})

	t.Run("malformed backend name is rejected with 400", func(t *testing.T) {
		_, beta := setupTwoImportExportBackends(t, "alpha", "beta")
		ctx := newTestHandlerContext()
		pem := getWrappingPublicKeyPEM(t, beta.backend.wrappingKey)

		wrapW := doWrap(ctx, wrapRequestBody(t, "Bad Backend!", pem))
		assert.Equal(t, http.StatusBadRequest, wrapW.Code)

		unwrapW := doUnwrap(ctx, unwrapRequestBody(t, "Bad Backend!", pem, base64.StdEncoding.EncodeToString([]byte("ct"))))
		assert.Equal(t, http.StatusBadRequest, unwrapW.Code)
	})

	t.Run("backend without import support is rejected with 501", func(t *testing.T) {
		capable := newMockKeyStoreWithImportExport()

		xkms.Reset()
		err := xkms.Initialize(&xkms.ServiceConfig{
			Backends: map[string]xkms.Backend{
				"capable": capable,
				"plain":   xkmsmocks.NewMockKeyStore(),
			},
			DefaultBackend: "capable",
		})
		require.NoError(t, err)
		t.Cleanup(xkms.Reset)

		ctx := newTestHandlerContext()
		pem := getWrappingPublicKeyPEM(t, capable.backend.wrappingKey)

		var capableCalls atomic.Int64
		countingWrap(capable, "wrapped-by-capable", &capableCalls)

		// WrapKey and UnwrapKey are both half of the import ceremony, and the
		// service resolves the named backend's import capability
		// (backend.ImportBackend, never the full ImportExportBackend union)
		// the same way ImportKey does, so an incapable backend is reported as
		// the typed xkms.ErrOperationNotSupported, 501 Not Implemented -- a
		// capability boundary, not a malformed request -- rather than the old
		// undifferentiated "does not support import/export" 400.
		wrapW := doWrap(ctx, wrapRequestBody(t, "plain", pem))
		assert.Equal(t, http.StatusNotImplemented, wrapW.Code)
		assert.Contains(t, wrapW.Body.String(), xkms.ErrOperationNotSupported.Error())
		assert.Equal(t, int64(0), capableCalls.Load(), "an incapable named backend must not fall back to a capable one")

		unwrapW := doUnwrap(ctx, unwrapRequestBody(t, "plain", pem, base64.StdEncoding.EncodeToString([]byte("ct"))))
		assert.Equal(t, http.StatusNotImplemented, unwrapW.Code)
		assert.Contains(t, unwrapW.Body.String(), xkms.ErrOperationNotSupported.Error())
	})
}
