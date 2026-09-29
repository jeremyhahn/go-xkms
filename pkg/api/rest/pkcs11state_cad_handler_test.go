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

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/pkcs11state"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newPKCS11StateHandlersForTest wires the handlers to a real XKMSService over
// an in-memory store, so the handler test exercises the same decode → service
// → store path production does.
func newPKCS11StateHandlersForTest(t *testing.T, backend storage.Backend) (*PKCS11StateHandlers, *xkms.XKMSService) {
	t.Helper()
	store, err := pkcs11state.NewStore(backend)
	require.NoError(t, err)
	svc := &xkms.XKMSService{}
	svc.SetPKCS11StateStore(store)
	return NewPKCS11StateHandlers(svc), svc
}

func postPKCS11StateCAD(t *testing.T, h *PKCS11StateHandlers, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/pkcs11state/compare-and-delete", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.CADHandler(rec, req)
	return rec
}

func TestPKCS11StateCADHandler_ReleasesOnlyTheObservedValue(t *testing.T) {
	h, svc := newPKCS11StateHandlersForTest(t, storage.NewMemory())
	ctx := context.Background()
	_, err := svc.PKCS11StatePut(ctx, &transport.PKCS11StatePutRequest{
		Token: "tok0", Key: "pkcs11/markers/claim", Value: []byte("holder-A"),
	})
	require.NoError(t, err)

	stale, err := json.Marshal(transport.PKCS11StateCADRequest{Token: "tok0", Key: "pkcs11/markers/claim", Expected: []byte("holder-B")})
	require.NoError(t, err)
	rec := postPKCS11StateCAD(t, h, stale)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var resp transport.PKCS11StateCADResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.False(t, resp.Deleted, "a guard that does not match is a refusal, not an error")

	observed, err := json.Marshal(transport.PKCS11StateCADRequest{Token: "tok0", Key: "pkcs11/markers/claim", Expected: []byte("holder-A")})
	require.NoError(t, err)
	rec = postPKCS11StateCAD(t, h, observed)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.True(t, resp.Deleted)

	got, err := svc.PKCS11StateGet(ctx, &transport.PKCS11StateGetRequest{Token: "tok0", Key: "pkcs11/markers/claim"})
	require.NoError(t, err)
	assert.False(t, got.Found)
}

func TestPKCS11StateCADHandler_RejectsBadInput(t *testing.T) {
	h, _ := newPKCS11StateHandlersForTest(t, storage.NewMemory())

	rec := postPKCS11StateCAD(t, h, []byte("{not json"))
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	missingToken, err := json.Marshal(transport.PKCS11StateCADRequest{Key: "pkcs11/markers/claim"})
	require.NoError(t, err)
	rec = postPKCS11StateCAD(t, h, missingToken)
	// A missing token is a fault in the request itself: it is reported at 400
	// with its own client-facing text, not withheld behind the internal-error
	// message (go-xkms#1118 withholds server faults, not 4xx validation
	// messages; go-xkms#1114/#1115 classify a missing token as a request
	// fault via IsPKCS11StateRequestError).
	assert.Equal(t, http.StatusBadRequest, rec.Code, "a missing token is a fault in the request")
	assert.Contains(t, rec.Body.String(), xkms.ErrPKCS11StateTokenRequired.Error())

	unwired := NewPKCS11StateHandlers(nil)
	rec = postPKCS11StateCAD(t, unwired, missingToken)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// noGuardedDeleteBackend hides every optional capability of the backend it
// wraps, so the store's refusal to emulate the guard reaches the wire as an
// error rather than a plausible-looking deleted=false.
type noGuardedDeleteBackend struct {
	storage.Backend
}

func TestPKCS11StateCADHandler_UnsupportedBackendIsAnError(t *testing.T) {
	h, svc := newPKCS11StateHandlersForTest(t, noGuardedDeleteBackend{Backend: storage.NewMemory()})
	_, err := svc.PKCS11StatePut(context.Background(), &transport.PKCS11StatePutRequest{
		Token: "tok0", Key: "pkcs11/markers/claim", Value: []byte("holder-A"),
	})
	require.NoError(t, err)

	body, err := json.Marshal(transport.PKCS11StateCADRequest{Token: "tok0", Key: "pkcs11/markers/claim", Expected: []byte("holder-A")})
	require.NoError(t, err)
	rec := postPKCS11StateCAD(t, h, body)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), ErrInternalError.Error())
	assert.NotContains(t, rec.Body.String(), pkcs11state.ErrCompareAndDeleteUnsupported.Error())
}
