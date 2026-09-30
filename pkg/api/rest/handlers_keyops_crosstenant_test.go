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
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ===========================================================================
// Cross-tenant isolation for the key lifecycle handlers (go-xkms#1218).
//
// Tenant A, authenticated, names a key that belongs to tenant B. Every one of
// Delete, Get, List, Rotate, Export and Copy must behave as if the key did not
// exist: the same status and the same body a genuinely missing key gets, so
// the response reveals neither the key nor the fact that another tenant holds
// it. Side effects are asserted too -- a handler that answered 404 after
// deleting the key would still be a breach.
// ===========================================================================

const (
	crossTenantSource = "primary"
	crossTenantDest   = "replica"
	crossTenantA      = "tenant-a"
	crossTenantB      = "tenant-b"
	crossTenantAKey   = "a-key"
	crossTenantBKey   = "b-key"
	crossTenantWrap   = string(backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
)

// crossTenantHandlerContext returns a HandlerContext over two software
// backends. The source backend holds one exportable ECDSA key for each holder
// tenant (tenant A and tenant B when none are named); the destination backend
// is empty.
func crossTenantHandlerContext(t *testing.T, holders ...string) (*HandlerContext, *xkms.XKMSService) {
	t.Helper()

	xkms.Reset()
	t.Cleanup(xkms.Reset)

	backends := make(map[string]xkms.Backend, 2)
	for _, name := range []string{crossTenantSource, crossTenantDest} {
		be, err := software.NewBackend(&software.Config{KeyStorage: storage.New()})
		require.NoError(t, err)
		ks, err := xkms.New(&xkms.BackendConfig{Backend: be, CertStorage: storage.New()})
		require.NoError(t, err)
		backends[name] = ks
	}
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       backends,
		DefaultBackend: crossTenantSource,
	}))
	svc, err := xkms.Get()
	require.NoError(t, err)
	wireKeyVersionStore(t)

	keyOf := map[string]string{crossTenantA: crossTenantAKey, crossTenantB: crossTenantBKey}
	if len(holders) == 0 {
		holders = []string{crossTenantA, crossTenantB}
	}
	for _, tenant := range holders {
		cn := keyOf[tenant]
		scoped, err := svc.LookupTenantBackend(crossTenantSource, tenant)
		require.NoError(t, err)
		_, err = scoped.GenerateECDSA(context.Background(), &types.KeyAttributes{
			CN:            cn,
			KeyType:       types.KeyTypeSigning,
			StoreType:     types.StoreSoftware,
			KeyAlgorithm:  x509.ECDSA,
			ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
			Exportable:    true,
		})
		require.NoError(t, err, "generating %s for %s", cn, tenant)
	}

	return &HandlerContext{xkmsService: svc}, svc
}

// tenantKeys lists the keys tenantID can see in the named backend.
func tenantKeys(t *testing.T, svc *xkms.XKMSService, backendName, tenantID string) []*types.KeyAttributes {
	t.Helper()
	scoped, err := svc.LookupTenantBackend(backendName, tenantID)
	require.NoError(t, err)
	keys, err := scoped.ListKeys(context.Background())
	require.NoError(t, err)
	return keys
}

// requireTenantBKeyIntact proves tenant B still holds its key, untouched.
func requireTenantBKeyIntact(t *testing.T, svc *xkms.XKMSService) {
	t.Helper()
	keys := tenantKeys(t, svc, crossTenantSource, crossTenantB)
	require.Len(t, keys, 1, "tenant B lost its key to tenant A")
	require.Equal(t, crossTenantBKey, keys[0].CN)
}

// crossTenantRoute describes one key-by-ID handler under test: how to route
// it and how to build a request naming keyID as tenant A.
type crossTenantRoute struct {
	name    string
	method  string
	pattern string
	handler func(*HandlerContext) http.HandlerFunc
	request func(t *testing.T, keyID string) *http.Request
}

func crossTenantRoutes() []crossTenantRoute {
	byID := func(method, suffix string, body interface{}) func(*testing.T, string) *http.Request {
		return func(t *testing.T, keyID string) *http.Request {
			return tenantIdentityRequest(t, method,
				"/api/v1/keys/"+keyID+suffix+"?backend="+crossTenantSource, body, crossTenantA)
		}
	}
	return []crossTenantRoute{
		{
			name: "delete", method: http.MethodDelete, pattern: "/api/v1/keys/{id}",
			handler: func(h *HandlerContext) http.HandlerFunc { return h.DeleteKeyHandler },
			request: byID(http.MethodDelete, "", nil),
		},
		{
			name: "get", method: http.MethodGet, pattern: "/api/v1/keys/{id}",
			handler: func(h *HandlerContext) http.HandlerFunc { return h.GetKeyHandler },
			request: byID(http.MethodGet, "", nil),
		},
		{
			name: "rotate", method: http.MethodPost, pattern: "/api/v1/keys/{id}/rotate",
			handler: func(h *HandlerContext) http.HandlerFunc { return h.RotateKeyHandler },
			request: byID(http.MethodPost, "/rotate", nil),
		},
		{
			name: "export", method: http.MethodPost, pattern: "/api/v1/keys/{id}/export",
			handler: func(h *HandlerContext) http.HandlerFunc { return h.ExportKeyHandler },
			request: byID(http.MethodPost, "/export", &ExportKeyRequest{Algorithm: crossTenantWrap}),
		},
		{
			name: "copy", method: http.MethodPost, pattern: "/api/v1/keys/copy",
			handler: func(h *HandlerContext) http.HandlerFunc { return h.CopyKeyHandler },
			request: func(t *testing.T, keyID string) *http.Request {
				return tenantIdentityRequest(t, http.MethodPost, "/api/v1/keys/copy", &CopyKeyRequest{
					SourceBackend: crossTenantSource,
					SourceKeyID:   keyID,
					DestBackend:   crossTenantDest,
					DestKeyID:     "stolen",
					Algorithm:     crossTenantWrap,
				}, crossTenantA)
			},
		},
	}
}

// TestKeyLifecycleHandlers_CrossTenantRefusalEqualsGenuineMiss is the
// go-xkms#1218 regression for REST. For each handler, tenant A naming tenant
// B's key must get exactly the response -- status and body -- tenant A gets
// for the same key ID in a deployment where no tenant holds it, and tenant
// B's key must survive the attempt. The genuine miss names the same ID so an
// echoed key ID cannot make two equivalent answers look different.
func TestKeyLifecycleHandlers_CrossTenantRefusalEqualsGenuineMiss(t *testing.T) {
	for _, route := range crossTenantRoutes() {
		t.Run(route.name, func(t *testing.T) {
			h, _ := crossTenantHandlerContext(t, crossTenantA)
			miss := httptest.NewRecorder()
			createRouterWithHandler(route.method, route.pattern, route.handler(h)).
				ServeHTTP(miss, route.request(t, crossTenantBKey))
			require.Equal(t, http.StatusNotFound, miss.Code,
				"a genuinely missing key must be 404: %s", miss.Body.String())

			h, svc := crossTenantHandlerContext(t)
			cross := httptest.NewRecorder()
			createRouterWithHandler(route.method, route.pattern, route.handler(h)).
				ServeHTTP(cross, route.request(t, crossTenantBKey))
			assert.Equal(t, miss.Code, cross.Code,
				"tenant A reached tenant B's key: %s", cross.Body.String())
			assert.Equal(t, miss.Body.String(), cross.Body.String(),
				"a cross-tenant refusal must be indistinguishable from a genuine miss")

			requireTenantBKeyIntact(t, svc)
			assert.Empty(t, tenantKeys(t, svc, crossTenantDest, ""),
				"no key may be created in the destination backend")
		})
	}
}

// TestRotateKeyHandler_CrossTenantDoesNotReplaceKey pins the rotation side
// effect precisely: tenant B's public key after tenant A's attempt must be
// the one it had before.
func TestRotateKeyHandler_CrossTenantDoesNotReplaceKey(t *testing.T) {
	h, svc := crossTenantHandlerContext(t)
	scopedB, err := svc.LookupTenantBackend(crossTenantSource, crossTenantB)
	require.NoError(t, err)
	attrs := tenantKeys(t, svc, crossTenantSource, crossTenantB)[0]
	before, err := scopedB.GetKey(context.Background(), attrs)
	require.NoError(t, err)

	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/rotate", h.RotateKeyHandler)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, tenantIdentityRequest(t, http.MethodPost,
		"/api/v1/keys/"+crossTenantBKey+"/rotate?backend="+crossTenantSource, nil, crossTenantA))
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())

	after, err := scopedB.GetKey(context.Background(), attrs)
	require.NoError(t, err)
	assert.Equal(t, publicKeyDER(t, before), publicKeyDER(t, after),
		"tenant A rotated tenant B's key")
}

// TestListKeysHandler_ShowsOnlyTheCallersKeys proves a tenant listing a
// shared backend sees its own key and never another tenant's.
func TestListKeysHandler_ShowsOnlyTheCallersKeys(t *testing.T) {
	h, _ := crossTenantHandlerContext(t)
	router := createRouterWithHandler(http.MethodGet, "/api/v1/keys", h.ListKeysHandler)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, tenantIdentityRequest(t, http.MethodGet,
		"/api/v1/keys?backend="+crossTenantSource, nil, crossTenantA))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var resp ListKeysResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	ids := make([]string, 0, len(resp.Keys))
	for _, k := range resp.Keys {
		ids = append(ids, k.KeyID)
	}
	assert.Equal(t, []string{crossTenantAKey}, ids,
		"tenant A must see exactly its own key")
	assert.Equal(t, 1, resp.Pagination.Total,
		"the total must not count another tenant's keys")
}

// TestKeyLifecycleHandlers_OwnKeyStillReachable is the positive control: the
// same handlers, naming tenant A's own key, succeed. Without it, a handler
// that refused every request would pass the isolation tests above.
func TestKeyLifecycleHandlers_OwnKeyStillReachable(t *testing.T) {
	for _, route := range crossTenantRoutes() {
		t.Run(route.name, func(t *testing.T) {
			h, _ := crossTenantHandlerContext(t)
			router := createRouterWithHandler(route.method, route.pattern, route.handler(h))

			w := httptest.NewRecorder()
			router.ServeHTTP(w, route.request(t, crossTenantAKey))
			assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
		})
	}
}

// TestCopyKeyHandler_CopyStaysInTheCallersTenant proves the copy a tenant
// makes of its own key lands in that tenant's scope in the destination: it
// is visible to the copying tenant and to no other.
func TestCopyKeyHandler_CopyStaysInTheCallersTenant(t *testing.T) {
	h, svc := crossTenantHandlerContext(t)
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/copy", h.CopyKeyHandler)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, tenantIdentityRequest(t, http.MethodPost, "/api/v1/keys/copy", &CopyKeyRequest{
		SourceBackend: crossTenantSource,
		SourceKeyID:   crossTenantAKey,
		DestBackend:   crossTenantDest,
		DestKeyID:     "a-copy",
		Algorithm:     crossTenantWrap,
	}, crossTenantA))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	own := tenantKeys(t, svc, crossTenantDest, crossTenantA)
	require.Len(t, own, 1, "the copy must be visible to the tenant that made it")
	assert.Equal(t, "a-copy", own[0].CN)
	assert.Equal(t, crossTenantA, own[0].TenantID)
	assert.Empty(t, tenantKeys(t, svc, crossTenantDest, crossTenantB),
		"the copy must not be visible to another tenant")
}

// publicKeyDER returns the PKIX DER encoding of key's public half.
func publicKeyDER(t *testing.T, key crypto.PrivateKey) []byte {
	t.Helper()
	signer, ok := key.(crypto.Signer)
	require.True(t, ok, "%T is not a crypto.Signer", key)
	der, err := x509.MarshalPKIXPublicKey(signer.Public())
	require.NoError(t, err)
	return der
}
