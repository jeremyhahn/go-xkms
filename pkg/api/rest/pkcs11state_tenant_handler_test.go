// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// TestPKCS11StateHandlers_TenantComesFromTheIdentity drives #1114 over REST: a
// tenant-A caller that names tenant B in the body gets 400 and cannot read B's
// record, while its own tenant, stated or omitted, reads its own record.
func TestPKCS11StateHandlers_TenantComesFromTheIdentity(t *testing.T) {
	h, svc := newPKCS11StateHandlersForTest(t, storage.NewMemory())
	ctxB := auth.WithIdentity(t.Context(), &auth.Identity{Subject: "bob", TenantID: "tenant-b"})
	_, err := svc.PKCS11StatePut(ctxB, &transport.PKCS11StatePutRequest{Token: "tok0", Key: "pkcs11/tokens/0", Value: []byte("b-state")})
	require.NoError(t, err)

	get := func(tenantID string) *httptest.ResponseRecorder {
		body, err := json.Marshal(transport.PKCS11StateGetRequest{TenantID: tenantID, Token: "tok0", Key: "pkcs11/tokens/0"})
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/pkcs11state/get", bytes.NewReader(body))
		req = req.WithContext(auth.WithIdentity(req.Context(), &auth.Identity{Subject: "alice", TenantID: "tenant-a"}))
		rec := httptest.NewRecorder()
		h.GetHandler(rec, req)
		return rec
	}

	rec := get("tenant-b")
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), xkms.ErrPKCS11StateTenantMismatch.Error())
	assert.NotContains(t, rec.Body.String(), "b-state")

	for _, own := range []string{"", "tenant-a"} {
		rec = get(own)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var resp transport.PKCS11StateGetResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		assert.False(t, resp.Found, "tenant A's namespace does not hold tenant B's record")
	}
}
