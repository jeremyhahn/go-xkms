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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ===========================================================================
// Tenant scoping for the key operation handlers.
//
// The tenant an operation runs under comes from the authenticated identity,
// as it always has on the gRPC transport. These handlers used to decode it
// straight out of the request body, so any caller could name any tenant.
// ===========================================================================

// tenantIdentityRequest builds a request whose context carries an
// authenticated identity belonging to tenantID. An empty tenantID produces a
// request with no identity at all.
func tenantIdentityRequest(t *testing.T, method, path string, body interface{}, tenantID string) *http.Request {
	t.Helper()

	buf := bytes.NewBuffer(nil)
	if body != nil {
		data, err := json.Marshal(body)
		require.NoError(t, err)
		buf = bytes.NewBuffer(data)
	}
	req := httptest.NewRequest(method, path, buf)
	if tenantID != "" {
		req = req.WithContext(auth.WithIdentity(req.Context(),
			&auth.Identity{Subject: "svc", TenantID: tenantID}))
	}
	return req
}

// TestKeyOpsHandlers_RejectBodySuppliedTenant proves every handler that
// decodes a request body refuses a caller-supplied tenant, with the exact
// error, rather than acting on it or quietly ignoring it.
func TestKeyOpsHandlers_RejectBodySuppliedTenant(t *testing.T) {
	tests := []struct {
		name    string
		handler func(*HandlerContext) http.HandlerFunc
		path    string
		body    interface{}
	}{
		{
			name:    "attest",
			handler: func(h *HandlerContext) http.HandlerFunc { return h.AttestKeyHandler },
			path:    "/api/v1/attest",
			body: &transport.AttestKeyRequest{
				Backend: "hardware", KeyID: "idevid", TenantID: "tenant-b",
			},
		},
		{
			name:    "derive-ecdh",
			handler: func(h *HandlerContext) http.HandlerFunc { return h.DeriveKeyECDHHandler },
			path:    "/api/v1/keys/derive-ecdh",
			body: &transport.DeriveKeyECDHRequest{
				KeyID: "ecdh-key", Backend: "hardware", PeerPublicKey: []byte("peer"), TenantID: "tenant-b",
			},
		},
		{
			name:    "wrap-by-id",
			handler: func(h *HandlerContext) http.HandlerFunc { return h.WrapKeyByIDHandler },
			path:    "/api/v1/keys/wrap-by-id",
			body: &transport.WrapKeyByIDRequest{
				WrappingKeyID: "kek", WrappingKeyBackend: "hardware",
				TargetKeyID: "target-key", TargetKeyBackend: "hardware",
				Algorithm: "RSAES_OAEP_SHA_256", TenantID: "tenant-b",
			},
		},
		{
			name:    "unwrap-by-id",
			handler: func(h *HandlerContext) http.HandlerFunc { return h.UnwrapKeyByIDHandler },
			path:    "/api/v1/keys/unwrap-by-id",
			body: &transport.UnwrapKeyByIDRequest{
				WrappedKey: []byte("blob"), UnwrappingKeyID: "kek",
				UnwrappingKeyBackend: "hardware", Algorithm: "RSAES_OAEP_SHA_256",
				TargetKeyID: "imported", TargetKeyBackend: "hardware", TenantID: "tenant-b",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, provider := setupKeyOpsHandlerContext(t)
			provider.addKey(&types.KeyAttributes{CN: "idevid"})
			provider.addKey(&types.KeyAttributes{CN: "ecdh-key"})
			provider.addKey(&types.KeyAttributes{CN: "kek"})
			provider.addKey(&types.KeyAttributes{CN: "target-key", Exportable: true})

			req := tenantIdentityRequest(t, http.MethodPost, tt.path, tt.body, "tenant-a")
			w := httptest.NewRecorder()
			tt.handler(h)(w, req)

			require.Equal(t, http.StatusBadRequest, w.Code,
				"a caller-named tenant must be refused, not acted on")
			assert.Contains(t, w.Body.String(), ErrTenantIDNotAccepted.Error())
		})
	}
}

// TestKeyOpsHandlers_AcceptRequestWithoutTenantField is the positive control
// for the rejection above: the same requests, without the field, must reach
// the service layer. Without it, a handler that refused everything would pass
// the rejection tests.
func TestKeyOpsHandlers_AcceptRequestWithoutTenantField(t *testing.T) {
	h, provider := setupKeyOpsHandlerContext(t)
	provider.attestation = &attestation.AttestationStatement{Format: "tpm2", Backend: "tpm2"}
	provider.addKey(&types.KeyAttributes{CN: "idevid"})

	req := tenantIdentityRequest(t, http.MethodPost, "/api/v1/attest",
		&transport.AttestKeyRequest{Backend: "hardware", KeyID: "idevid"}, "")
	w := httptest.NewRecorder()
	h.AttestKeyHandler(w, req)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

// TestAttestKeyHandler_UsesAuthenticatedTenant proves the tenant that reaches
// the service layer is the authenticated caller's.
//
// The oracle is which key resolves: the fixture holds one key per tenant, and
// a tenant-scoped view of the backend contains only that tenant's. A caller
// authenticated as one tenant therefore reaches its own key and cannot reach
// the other's, which no amount of dropping or defaulting the tenant would
// reproduce.
func TestAttestKeyHandler_UsesAuthenticatedTenant(t *testing.T) {
	h, provider := setupKeyOpsHandlerContext(t)
	provider.attestation = &attestation.AttestationStatement{Format: "tpm2", Backend: "tpm2"}
	provider.addKey(&types.KeyAttributes{CN: "a-key", TenantID: "tenant-a"})
	provider.addKey(&types.KeyAttributes{CN: "b-key", TenantID: "tenant-b"})

	attest := func(keyID, tenantID string) *httptest.ResponseRecorder {
		req := tenantIdentityRequest(t, http.MethodPost, "/api/v1/attest",
			&transport.AttestKeyRequest{Backend: "hardware", KeyID: keyID}, tenantID)
		w := httptest.NewRecorder()
		h.AttestKeyHandler(w, req)
		return w
	}

	own := attest("a-key", "tenant-a")
	require.Equal(t, http.StatusOK, own.Code,
		"a tenant must reach its own key: %s", own.Body.String())

	foreign := attest("b-key", "tenant-a")
	assert.NotEqual(t, http.StatusOK, foreign.Code,
		"a tenant must not reach another tenant's key by naming it")

	ownB := attest("b-key", "tenant-b")
	require.Equal(t, http.StatusOK, ownB.Code,
		"the other tenant must reach its own key: %s", ownB.Body.String())
}

// TestExportKeyMaterialHandler_UsesAuthenticatedTenant covers the one handler
// whose request carries no body, so the tenant can only come from the
// identity. The fixture returns material naming the tenant of the key it
// resolved, making the returned bytes the oracle.
func TestExportKeyMaterialHandler_UsesAuthenticatedTenant(t *testing.T) {
	h, provider := setupKeyOpsHandlerContext(t)
	provider.addKey(&types.KeyAttributes{
		CN:                 "tenant-a-aes",
		TenantID:           "tenant-a",
		KeyType:            types.KeyTypeSecret,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	})
	provider.addKey(&types.KeyAttributes{
		CN:                 "plain-aes",
		KeyType:            types.KeyTypeSecret,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	})

	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/export-material", h.ExportKeyMaterialHandler)
	export := func(keyID, tenantID string) *httptest.ResponseRecorder {
		req := tenantIdentityRequest(t, http.MethodPost,
			"/api/v1/keys/"+keyID+"/export-material?backend=hardware", nil, tenantID)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	own := export("tenant-a-aes", "tenant-a")
	require.Equal(t, http.StatusOK, own.Code, own.Body.String())
	var resp transport.ExportKeyMaterialResponse
	require.NoError(t, json.Unmarshal(own.Body.Bytes(), &resp))
	assert.Equal(t, []byte("key-material-for-tenant-a"), resp.KeyMaterial,
		"the material must come from the key the authenticated tenant owns")

	foreign := export("tenant-a-aes", "tenant-b")
	assert.NotEqual(t, http.StatusOK, foreign.Code,
		"another tenant must not export this key's material")

	// Positive control: an unauthenticated caller still reaches the
	// untenanted key, so single-tenant deployments are unaffected.
	untenanted := export("plain-aes", "")
	require.Equal(t, http.StatusOK, untenanted.Code, untenanted.Body.String())
	require.NoError(t, json.Unmarshal(untenanted.Body.Bytes(), &resp))
	assert.Equal(t, provider.exportedMaterial, resp.KeyMaterial)
}
