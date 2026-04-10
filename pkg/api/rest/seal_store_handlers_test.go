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
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestSealStoreHandlers(t *testing.T) *SealStoreHandlers {
	t.Helper()
	store := storage.NewMemory()
	ps, err := seal.NewPlatformStore(store, slog.Default())
	require.NoError(t, err)
	return NewSealStoreHandlers(ps)
}

func sealStoreRouter(h *SealStoreHandlers) *chi.Mux {
	r := chi.NewRouter()
	r.Put("/api/v1/platform-store/{name}", h.PutSecretHandler)
	r.Get("/api/v1/platform-store/{name}", h.GetSecretHandler)
	r.Delete("/api/v1/platform-store/{name}", h.DeleteSecretHandler)
	r.Get("/api/v1/platform-store", h.ListSecretsHandler)
	r.Post("/api/v1/platform-store/{name}/reseal", h.ResealSecretHandler)
	r.Get("/api/v1/platform-store/status", h.StatusHandler)
	return r
}

// --- PutSecretHandler ---

func TestSealStore_PutSecret_Success(t *testing.T) {
	h := newTestSealStoreHandlers(t)
	r := sealStoreRouter(h)

	secret := base64.StdEncoding.EncodeToString([]byte("my-secret"))
	body := `{"name":"db-pass","secret":"` + secret + `"}`

	req := httptest.NewRequest(http.MethodPut, "/api/v1/platform-store/db-pass",
		strings.NewReader(body))
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp SealStorePutResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "db-pass", resp.Name)
}

func TestSealStore_PutSecret_MissingName(t *testing.T) {
	h := newTestSealStoreHandlers(t)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/platform-store/", nil)
	w := httptest.NewRecorder()

	h.PutSecretHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSealStore_PutSecret_InvalidJSON(t *testing.T) {
	h := newTestSealStoreHandlers(t)
	r := sealStoreRouter(h)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/platform-store/test",
		strings.NewReader(`{bad`))
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSealStore_PutSecret_EmptySecret(t *testing.T) {
	h := newTestSealStoreHandlers(t)
	r := sealStoreRouter(h)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/platform-store/test",
		strings.NewReader(`{"name":"test","secret":""}`))
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSealStore_PutSecret_InvalidBase64(t *testing.T) {
	h := newTestSealStoreHandlers(t)
	r := sealStoreRouter(h)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/platform-store/test",
		strings.NewReader(`{"name":"test","secret":"not-valid-base64!!!"}`))
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- GetSecretHandler ---

func TestSealStore_GetSecret_Success(t *testing.T) {
	h := newTestSealStoreHandlers(t)
	r := sealStoreRouter(h)

	secret := base64.StdEncoding.EncodeToString([]byte("my-secret"))
	body := `{"name":"api-key","secret":"` + secret + `"}`

	putReq := httptest.NewRequest(http.MethodPut, "/api/v1/platform-store/api-key",
		strings.NewReader(body))
	putW := httptest.NewRecorder()
	r.ServeHTTP(putW, putReq)
	require.Equal(t, http.StatusOK, putW.Code)

	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/platform-store/api-key", nil)
	getW := httptest.NewRecorder()
	r.ServeHTTP(getW, getReq)

	assert.Equal(t, http.StatusOK, getW.Code)
	var resp SealStoreGetResponse
	require.NoError(t, json.Unmarshal(getW.Body.Bytes(), &resp))
	assert.Equal(t, "api-key", resp.Name)

	decoded, err := base64.StdEncoding.DecodeString(resp.Secret)
	require.NoError(t, err)
	assert.Equal(t, "my-secret", string(decoded))
}

func TestSealStore_GetSecret_NotFound(t *testing.T) {
	h := newTestSealStoreHandlers(t)
	r := sealStoreRouter(h)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/platform-store/nonexistent", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestSealStore_GetSecret_MissingName(t *testing.T) {
	h := newTestSealStoreHandlers(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/platform-store/", nil)
	w := httptest.NewRecorder()

	h.GetSecretHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- DeleteSecretHandler ---

func TestSealStore_DeleteSecret_Success(t *testing.T) {
	h := newTestSealStoreHandlers(t)
	r := sealStoreRouter(h)

	secret := base64.StdEncoding.EncodeToString([]byte("delete-me"))
	putReq := httptest.NewRequest(http.MethodPut, "/api/v1/platform-store/temp",
		strings.NewReader(`{"name":"temp","secret":"`+secret+`"}`))
	putW := httptest.NewRecorder()
	r.ServeHTTP(putW, putReq)
	require.Equal(t, http.StatusOK, putW.Code)

	delReq := httptest.NewRequest(http.MethodDelete, "/api/v1/platform-store/temp", nil)
	delW := httptest.NewRecorder()
	r.ServeHTTP(delW, delReq)

	assert.Equal(t, http.StatusOK, delW.Code)
}

func TestSealStore_DeleteSecret_NotFound(t *testing.T) {
	h := newTestSealStoreHandlers(t)
	r := sealStoreRouter(h)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/platform-store/ghost", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestSealStore_DeleteSecret_MissingName(t *testing.T) {
	h := newTestSealStoreHandlers(t)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/platform-store/", nil)
	w := httptest.NewRecorder()

	h.DeleteSecretHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- ListSecretsHandler ---

func TestSealStore_ListSecrets_Empty(t *testing.T) {
	h := newTestSealStoreHandlers(t)
	r := sealStoreRouter(h)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/platform-store", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp SealStoreListResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Empty(t, resp.Names)
	assert.Equal(t, 0, resp.Total)
}

func TestSealStore_ListSecrets_WithEntries(t *testing.T) {
	h := newTestSealStoreHandlers(t)
	r := sealStoreRouter(h)

	for _, name := range []string{"key1", "key2"} {
		secret := base64.StdEncoding.EncodeToString([]byte("val"))
		putReq := httptest.NewRequest(http.MethodPut, "/api/v1/platform-store/"+name,
			strings.NewReader(`{"name":"`+name+`","secret":"`+secret+`"}`))
		putW := httptest.NewRecorder()
		r.ServeHTTP(putW, putReq)
		require.Equal(t, http.StatusOK, putW.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/platform-store", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp SealStoreListResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 2, resp.Total)
}

// --- ResealSecretHandler ---

func TestSealStore_ResealSecret_Success(t *testing.T) {
	h := newTestSealStoreHandlers(t)
	r := sealStoreRouter(h)

	secret := base64.StdEncoding.EncodeToString([]byte("reseal-me"))
	putReq := httptest.NewRequest(http.MethodPut, "/api/v1/platform-store/resealable",
		strings.NewReader(`{"name":"resealable","secret":"`+secret+`"}`))
	putW := httptest.NewRecorder()
	r.ServeHTTP(putW, putReq)
	require.Equal(t, http.StatusOK, putW.Code)

	resealReq := httptest.NewRequest(http.MethodPost, "/api/v1/platform-store/resealable/reseal", nil)
	resealW := httptest.NewRecorder()
	r.ServeHTTP(resealW, resealReq)

	assert.Equal(t, http.StatusOK, resealW.Code)
	var resp SealStoreResealResponse
	require.NoError(t, json.Unmarshal(resealW.Body.Bytes(), &resp))
	assert.Equal(t, "resealable", resp.Name)
}

func TestSealStore_ResealSecret_NotFound(t *testing.T) {
	h := newTestSealStoreHandlers(t)
	r := sealStoreRouter(h)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/platform-store/ghost/reseal", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestSealStore_ResealSecret_MissingName(t *testing.T) {
	h := newTestSealStoreHandlers(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/platform-store//reseal", nil)
	w := httptest.NewRecorder()

	h.ResealSecretHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- StatusHandler ---

func TestSealStore_Status_Success(t *testing.T) {
	h := newTestSealStoreHandlers(t)
	r := sealStoreRouter(h)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/platform-store/status", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp SealStoreStatusResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Available)
	assert.Equal(t, 0, resp.Total)
}

// --- platformStoreWriteJSONError ---

func TestPlatformStoreWriteJSONError(t *testing.T) {
	w := httptest.NewRecorder()
	platformStoreWriteJSONError(w, "test error", http.StatusBadRequest)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "test error")
}

// --- mockPlatformStore for error paths ---

type mockPlatformStore struct {
	putErr    error
	getVal    []byte
	getErr    error
	deleteErr error
	listNames []string
	listErr   error
	resealErr error
	existsVal bool
	existsErr error
}

func (m *mockPlatformStore) Put(_ context.Context, _ string, _ []byte) error { return m.putErr }
func (m *mockPlatformStore) Get(_ context.Context, _ string) ([]byte, error) {
	return m.getVal, m.getErr
}
func (m *mockPlatformStore) Delete(_ context.Context, _ string) error { return m.deleteErr }
func (m *mockPlatformStore) Exists(_ context.Context, _ string) (bool, error) {
	return m.existsVal, m.existsErr
}
func (m *mockPlatformStore) List(_ context.Context) ([]string, error) {
	return m.listNames, m.listErr
}
func (m *mockPlatformStore) Reseal(_ context.Context, _ string) error { return m.resealErr }

func TestSealStore_PutSecret_InvalidSecretName(t *testing.T) {
	h := NewSealStoreHandlers(&mockPlatformStore{putErr: seal.ErrInvalidSecretName})
	r := chi.NewRouter()
	r.Put("/api/v1/platform-store/{name}", h.PutSecretHandler)

	secret := base64.StdEncoding.EncodeToString([]byte("val"))
	req := httptest.NewRequest(http.MethodPut, "/api/v1/platform-store/test",
		strings.NewReader(`{"name":"test","secret":"`+secret+`"}`))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSealStore_PutSecret_InternalError(t *testing.T) {
	h := NewSealStoreHandlers(&mockPlatformStore{putErr: errors.New("internal")})
	r := chi.NewRouter()
	r.Put("/api/v1/platform-store/{name}", h.PutSecretHandler)

	secret := base64.StdEncoding.EncodeToString([]byte("val"))
	req := httptest.NewRequest(http.MethodPut, "/api/v1/platform-store/test",
		strings.NewReader(`{"name":"test","secret":"`+secret+`"}`))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestSealStore_GetSecret_InvalidSecretName(t *testing.T) {
	h := NewSealStoreHandlers(&mockPlatformStore{getErr: seal.ErrInvalidSecretName})
	r := chi.NewRouter()
	r.Get("/api/v1/platform-store/{name}", h.GetSecretHandler)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/platform-store/bad", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSealStore_GetSecret_InternalError(t *testing.T) {
	h := NewSealStoreHandlers(&mockPlatformStore{getErr: errors.New("internal")})
	r := chi.NewRouter()
	r.Get("/api/v1/platform-store/{name}", h.GetSecretHandler)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/platform-store/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestSealStore_DeleteSecret_InvalidSecretName(t *testing.T) {
	h := NewSealStoreHandlers(&mockPlatformStore{deleteErr: seal.ErrInvalidSecretName})
	r := chi.NewRouter()
	r.Delete("/api/v1/platform-store/{name}", h.DeleteSecretHandler)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/platform-store/bad", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSealStore_DeleteSecret_InternalError(t *testing.T) {
	h := NewSealStoreHandlers(&mockPlatformStore{deleteErr: errors.New("internal")})
	r := chi.NewRouter()
	r.Delete("/api/v1/platform-store/{name}", h.DeleteSecretHandler)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/platform-store/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestSealStore_ListSecrets_Error(t *testing.T) {
	h := NewSealStoreHandlers(&mockPlatformStore{listErr: errors.New("internal")})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/platform-store", nil)
	w := httptest.NewRecorder()
	h.ListSecretsHandler(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestSealStore_ResealSecret_ResealFailed(t *testing.T) {
	h := NewSealStoreHandlers(&mockPlatformStore{resealErr: seal.ErrResealFailed})
	r := chi.NewRouter()
	r.Post("/api/v1/platform-store/{name}/reseal", h.ResealSecretHandler)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/platform-store/test/reseal", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestSealStore_ResealSecret_InternalError(t *testing.T) {
	h := NewSealStoreHandlers(&mockPlatformStore{resealErr: errors.New("internal")})
	r := chi.NewRouter()
	r.Post("/api/v1/platform-store/{name}/reseal", h.ResealSecretHandler)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/platform-store/test/reseal", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestSealStore_Status_Error(t *testing.T) {
	h := NewSealStoreHandlers(&mockPlatformStore{listErr: errors.New("internal")})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/platform-store/status", nil)
	w := httptest.NewRecorder()
	h.StatusHandler(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
