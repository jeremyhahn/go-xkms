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

package quic

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
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Tenant scoping for the key operation handlers.
//
// The tenant an operation runs under comes from the authenticated identity,
// as it always has on the gRPC transport. These handlers used to decode it
// straight out of the request body, so any caller could name any tenant.
// ============================================================================

// tenantRequest builds a POST request whose context carries an authenticated
// identity belonging to tenantID. An empty tenantID produces a request with no
// identity at all.
func tenantRequest(t *testing.T, path string, body interface{}, tenantID string) *http.Request {
	t.Helper()

	reader := bytes.NewReader(nil)
	if body != nil {
		data, err := json.Marshal(body)
		require.NoError(t, err)
		reader = bytes.NewReader(data)
	}
	req := httptest.NewRequest(http.MethodPost, path, reader)
	req.Header.Set("Content-Type", "application/json")
	if tenantID != "" {
		req = req.WithContext(auth.WithIdentity(req.Context(),
			&auth.Identity{Subject: "svc", TenantID: tenantID}))
	}
	return req
}

// TestKeyOpHandlers_RejectBodySuppliedTenant proves every handler that decodes
// a request body refuses a caller-supplied tenant, with the exact error,
// rather than acting on it or quietly ignoring it.
func TestKeyOpHandlers_RejectBodySuppliedTenant(t *testing.T) {
	tests := []struct {
		name    string
		handler func(*Server) http.HandlerFunc
		path    string
		body    interface{}
	}{
		{
			name:    "attest",
			handler: func(s *Server) http.HandlerFunc { return s.handleAttestKey },
			path:    "/api/v1/attest",
			body: &transport.AttestKeyRequest{
				Backend: "hardware", KeyID: "idevid", TenantID: "tenant-b",
			},
		},
		{
			name:    "derive-ecdh",
			handler: func(s *Server) http.HandlerFunc { return s.handleDeriveKeyECDH },
			path:    "/api/v1/keys/derive-ecdh",
			body: &transport.DeriveKeyECDHRequest{
				KeyID: "ecdh-key", Backend: "hardware", PeerPublicKey: []byte("peer"), TenantID: "tenant-b",
			},
		},
		{
			name:    "wrap-by-id",
			handler: func(s *Server) http.HandlerFunc { return s.handleWrapKeyByID },
			path:    "/api/v1/keys/wrap-by-id",
			body: &transport.WrapKeyByIDRequest{
				WrappingKeyID: "kek", WrappingKeyBackend: "hardware",
				TargetKeyID: "target-key", TargetKeyBackend: "hardware",
				Algorithm: "RSAES_OAEP_SHA_256", TenantID: "tenant-b",
			},
		},
		{
			name:    "unwrap-by-id",
			handler: func(s *Server) http.HandlerFunc { return s.handleUnwrapKeyByID },
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
			server, provider := createTestServerWithHardwareBackend(t)
			defer xkms.Reset()
			provider.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
				return []*types.KeyAttributes{{CN: "idevid"}, {CN: "ecdh-key"}, {CN: "kek"}}, nil
			}

			w := httptest.NewRecorder()
			tt.handler(server)(w, tenantRequest(t, tt.path, tt.body, "tenant-a"))

			require.Equal(t, http.StatusBadRequest, w.Code,
				"a caller-named tenant must be refused, not acted on")
			assert.Contains(t, w.Body.String(), ErrTenantIDNotAccepted.Error())
		})
	}
}

// TestHandleAttestKey_AcceptsRequestWithoutTenantField is the positive control
// for the rejection above: the same request, without the field, must reach the
// service layer. Without it, a handler that refused everything would pass the
// rejection tests.
func TestHandleAttestKey_AcceptsRequestWithoutTenantField(t *testing.T) {
	server, provider := createTestServerWithHardwareBackend(t)
	defer xkms.Reset()

	provider.attestResult = &attestation.AttestationStatement{Format: "tpm2", Backend: "tpm2"}
	provider.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{{CN: "idevid"}}, nil
	}

	w := httptest.NewRecorder()
	server.handleAttestKey(w, tenantRequest(t, "/api/v1/attest",
		&transport.AttestKeyRequest{Backend: "hardware", KeyID: "idevid"}, ""))

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

// TestHandleAttestKey_UsesAuthenticatedTenant proves the tenant that reaches
// the service layer is the authenticated caller's.
//
// The oracle is which key resolves: the fixture holds one key per tenant, and
// a tenant-scoped view of the backend contains only that tenant's. A caller
// authenticated as one tenant therefore reaches its own key and cannot reach
// the other's, which no amount of dropping or defaulting the tenant would
// reproduce.
func TestHandleAttestKey_UsesAuthenticatedTenant(t *testing.T) {
	server, provider := createTestServerWithHardwareBackend(t)
	defer xkms.Reset()

	provider.attestResult = &attestation.AttestationStatement{Format: "tpm2", Backend: "tpm2"}
	provider.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{CN: "a-key", TenantID: "tenant-a"},
			{CN: "b-key", TenantID: "tenant-b"},
		}, nil
	}

	attest := func(keyID, tenantID string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		server.handleAttestKey(w, tenantRequest(t, "/api/v1/attest",
			&transport.AttestKeyRequest{Backend: "hardware", KeyID: keyID}, tenantID))
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

// TestHandleExportKeyMaterial_UsesAuthenticatedTenant covers the one handler
// whose request carries no body, so the tenant can only come from the
// identity.
func TestHandleExportKeyMaterial_UsesAuthenticatedTenant(t *testing.T) {
	server, mockKS, ext := createTestServerWithExtended(t)
	defer xkms.Reset()

	material := []byte("0123456789abcdef0123456789abcdef")
	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{{
			CN:                 "sym-key",
			TenantID:           "tenant-a",
			KeyType:            types.KeyTypeSecret,
			SymmetricAlgorithm: types.SymmetricAES256GCM,
			Exportable:         true,
		}}, nil
	}
	ext.StoreSymmetricKey("sym-key", material)

	export := func(tenantID string) *httptest.ResponseRecorder {
		req := tenantRequest(t, "/api/v1/keys/sym-key/export-material?backend=software", nil, tenantID)
		w := httptest.NewRecorder()
		server.handleExportKeyMaterial(w, req, "sym-key", "software")
		return w
	}

	own := export("tenant-a")
	require.Equal(t, http.StatusOK, own.Code,
		"the owning tenant must be able to export its own key: %s", own.Body.String())
	var resp transport.ExportKeyMaterialResponse
	require.NoError(t, json.NewDecoder(own.Body).Decode(&resp))
	assert.Equal(t, material, resp.KeyMaterial)

	foreign := export("tenant-b")
	assert.NotEqual(t, http.StatusOK, foreign.Code,
		"another tenant must not export this key's material")

	// Positive control: an unauthenticated caller still reaches the unscoped
	// view, so single-tenant deployments are unaffected.
	untenanted := export("")
	require.Equal(t, http.StatusOK, untenanted.Code, untenanted.Body.String())
}
