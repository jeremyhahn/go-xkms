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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file covers PutHandler, PutIfAbsentHandler, CASHandler, GetHandler,
// DeleteHandler and ListHandler in pkcs11state_handlers.go (go-xkms #705,
// batch A); only CADHandler had a test. It reuses
// pkcs11state_cad_handler_test.go's newPKCS11StateHandlersForTest helper.

func postPKCS11State(t *testing.T, h *PKCS11StateHandlers, handlerFn http.HandlerFunc, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/pkcs11state/x", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handlerFn(rec, req)
	return rec
}

func TestPKCS11StatePutHandler_Success(t *testing.T) {
	h, svc := newPKCS11StateHandlersForTest(t, qrdbsdk.NewMemoryKVStore())
	body, err := json.Marshal(transport.PKCS11StatePutRequest{Token: "tok0", Key: "k", Value: []byte("v")})
	require.NoError(t, err)

	rec := postPKCS11State(t, h, h.PutHandler, body)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	got, err := svc.PKCS11StateGet(context.Background(), &transport.PKCS11StateGetRequest{Token: "tok0", Key: "k"})
	require.NoError(t, err)
	assert.True(t, got.Found)
	assert.Equal(t, []byte("v"), got.Value)
}

func TestPKCS11StatePutHandler_BadInput(t *testing.T) {
	h, _ := newPKCS11StateHandlersForTest(t, qrdbsdk.NewMemoryKVStore())
	rec := postPKCS11State(t, h, h.PutHandler, []byte("{not json"))
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	unwired := NewPKCS11StateHandlers(nil)
	rec = postPKCS11State(t, unwired, unwired.PutHandler, []byte("{}"))
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestPKCS11StatePutIfAbsentHandler_StoresOnlyOnce(t *testing.T) {
	h, _ := newPKCS11StateHandlersForTest(t, qrdbsdk.NewMemoryKVStore())
	body, err := json.Marshal(transport.PKCS11StatePutIfAbsentRequest{Token: "tok0", Key: "k", Value: []byte("first")})
	require.NoError(t, err)

	rec := postPKCS11State(t, h, h.PutIfAbsentHandler, body)
	require.Equal(t, http.StatusOK, rec.Code)
	var resp transport.PKCS11StatePutIfAbsentResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.True(t, resp.Stored)

	body2, err := json.Marshal(transport.PKCS11StatePutIfAbsentRequest{Token: "tok0", Key: "k", Value: []byte("second")})
	require.NoError(t, err)
	rec = postPKCS11State(t, h, h.PutIfAbsentHandler, body2)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.False(t, resp.Stored, "a key that already exists is never overwritten")
}

func TestPKCS11StatePutIfAbsentHandler_BadInput(t *testing.T) {
	h, _ := newPKCS11StateHandlersForTest(t, qrdbsdk.NewMemoryKVStore())
	rec := postPKCS11State(t, h, h.PutIfAbsentHandler, []byte("{not json"))
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestPKCS11StateCASHandler_SwapsOnlyOnMatch(t *testing.T) {
	h, svc := newPKCS11StateHandlersForTest(t, qrdbsdk.NewMemoryKVStore())
	_, err := svc.PKCS11StatePut(context.Background(), &transport.PKCS11StatePutRequest{Token: "tok0", Key: "k", Value: []byte("old")})
	require.NoError(t, err)

	body, err := json.Marshal(transport.PKCS11StateCASRequest{Token: "tok0", Key: "k", Expected: []byte("wrong"), New: []byte("new")})
	require.NoError(t, err)
	rec := postPKCS11State(t, h, h.CASHandler, body)
	require.Equal(t, http.StatusOK, rec.Code)
	var resp transport.PKCS11StateCASResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.False(t, resp.Swapped)

	body2, err := json.Marshal(transport.PKCS11StateCASRequest{Token: "tok0", Key: "k", Expected: []byte("old"), New: []byte("new")})
	require.NoError(t, err)
	rec = postPKCS11State(t, h, h.CASHandler, body2)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.True(t, resp.Swapped)
}

func TestPKCS11StateCASHandler_BadInput(t *testing.T) {
	h, _ := newPKCS11StateHandlersForTest(t, qrdbsdk.NewMemoryKVStore())
	rec := postPKCS11State(t, h, h.CASHandler, []byte("{not json"))
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestPKCS11StateGetHandler_NotFound(t *testing.T) {
	h, _ := newPKCS11StateHandlersForTest(t, qrdbsdk.NewMemoryKVStore())
	body, err := json.Marshal(transport.PKCS11StateGetRequest{Token: "tok0", Key: "missing"})
	require.NoError(t, err)
	rec := postPKCS11State(t, h, h.GetHandler, body)
	require.Equal(t, http.StatusOK, rec.Code, "a missing key is a not-found result, not an HTTP error")
	var resp transport.PKCS11StateGetResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.False(t, resp.Found)
}

func TestPKCS11StateGetHandler_BadInput(t *testing.T) {
	h, _ := newPKCS11StateHandlersForTest(t, qrdbsdk.NewMemoryKVStore())
	rec := postPKCS11State(t, h, h.GetHandler, []byte("{not json"))
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestPKCS11StateDeleteHandler_Success(t *testing.T) {
	h, svc := newPKCS11StateHandlersForTest(t, qrdbsdk.NewMemoryKVStore())
	_, err := svc.PKCS11StatePut(context.Background(), &transport.PKCS11StatePutRequest{Token: "tok0", Key: "k", Value: []byte("v")})
	require.NoError(t, err)

	body, err := json.Marshal(transport.PKCS11StateDeleteRequest{Token: "tok0", Key: "k"})
	require.NoError(t, err)
	rec := postPKCS11State(t, h, h.DeleteHandler, body)
	require.Equal(t, http.StatusOK, rec.Code)

	got, err := svc.PKCS11StateGet(context.Background(), &transport.PKCS11StateGetRequest{Token: "tok0", Key: "k"})
	require.NoError(t, err)
	assert.False(t, got.Found)
}

func TestPKCS11StateDeleteHandler_BadInput(t *testing.T) {
	h, _ := newPKCS11StateHandlersForTest(t, qrdbsdk.NewMemoryKVStore())
	rec := postPKCS11State(t, h, h.DeleteHandler, []byte("{not json"))
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestPKCS11StateListHandler_FiltersByPrefix(t *testing.T) {
	h, svc := newPKCS11StateHandlersForTest(t, qrdbsdk.NewMemoryKVStore())
	for _, key := range []string{"ns/a", "ns/b", "other/c"} {
		_, err := svc.PKCS11StatePut(context.Background(), &transport.PKCS11StatePutRequest{Token: "tok0", Key: key, Value: []byte("v")})
		require.NoError(t, err)
	}

	body, err := json.Marshal(transport.PKCS11StateListRequest{Token: "tok0", Prefix: "ns/"})
	require.NoError(t, err)
	rec := postPKCS11State(t, h, h.ListHandler, body)
	require.Equal(t, http.StatusOK, rec.Code)
	var resp transport.PKCS11StateListResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.ElementsMatch(t, []string{"ns/a", "ns/b"}, resp.Keys)
}

func TestPKCS11StateListHandler_BadInput(t *testing.T) {
	h, _ := newPKCS11StateHandlersForTest(t, qrdbsdk.NewMemoryKVStore())
	rec := postPKCS11State(t, h, h.ListHandler, []byte("{not json"))
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}
