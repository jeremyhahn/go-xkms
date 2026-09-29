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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/encoding"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ===========================================================================
// Cross-tenant isolation for the certificate and seal handlers (go-xkms#1228).
//
// Tenant A, authenticated, names state that belongs to tenant B or to the
// platform: B's certificate (by its bare ID and by B's storage namespace,
// "tenant-b/<id>"), the platform's unprefixed certificate, B's sealing key,
// and blobs B sealed. Every handler must answer exactly as it answers the same
// request in a deployment where that state does not exist, and must leave the
// state untouched.
// ===========================================================================

const (
	csBackend = "primary"
	csTenantA = "tenant-a"
	csTenantB = "tenant-b"
	csAKey    = "a-key"
	csBKey    = "b-key"
	csSysKey  = "sys"
	csSecret  = "tenant b's secret"
)

// csFixture is one deployment: the handler context, the service behind it,
// and the certificates it was seeded with.
type csFixture struct {
	h     *HandlerContext
	svc   *xkms.XKMSService
	certs map[string]*x509.Certificate
}

// csBlobs are the sealed blobs tenant B produced in the populated deployment.
type csBlobs struct {
	keyed      *types.SealedData
	defaultKey *transport.SealResponse
}

// newCSFixture builds a deployment over one software backend. Tenant A always
// holds an encryption key and a certificate under csAKey. When others is
// true, tenant B holds the same under csBKey (plus a chain), and the platform
// holds an untenanted key and certificate under csSysKey.
func newCSFixture(t *testing.T, others bool) *csFixture {
	t.Helper()

	xkms.Reset()
	t.Cleanup(xkms.Reset)

	be, err := software.NewBackend(&software.Config{KeyStorage: storage.New()})
	require.NoError(t, err)
	ks, err := xkms.New(&xkms.BackendConfig{Backend: be, CertStorage: storage.New()})
	require.NoError(t, err)
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{csBackend: ks},
		DefaultBackend: csBackend,
	}))
	svc, err := xkms.Get()
	require.NoError(t, err)

	f := &csFixture{h: &HandlerContext{xkmsService: svc}, svc: svc, certs: map[string]*x509.Certificate{}}
	f.seed(t, csTenantA, csAKey)
	if others {
		f.seed(t, csTenantB, csBKey)
		f.seed(t, "", csSysKey)
	}
	return f
}

// seed gives tenant (the platform when empty) an ECDSA encryption key named
// id and a certificate and one-element chain stored under the same id.
func (f *csFixture) seed(t *testing.T, tenant, id string) {
	t.Helper()
	b, err := f.svc.LookupTenantBackend(csBackend, tenant)
	require.NoError(t, err)
	_, err = b.GenerateECDSA(context.Background(), &types.KeyAttributes{
		CN:            id,
		KeyType:       types.KeyTypeEncryption,
		StoreType:     types.StoreSoftware,
		KeyAlgorithm:  x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
	})
	require.NoError(t, err)

	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := generateTestCertificate(t, certKey)
	require.NoError(t, b.SaveCert(context.Background(), id, cert))
	require.NoError(t, b.SaveCertChain(context.Background(), id, []*x509.Certificate{cert}))
	f.certs[tenant+"/"+id] = cert
}

// sealAsB produces tenant B's blobs: one under B's own key, and one under
// the default sealing key, sealed through the service as tenant B.
func (f *csFixture) sealAsB(t *testing.T) csBlobs {
	t.Helper()
	b, err := f.svc.LookupTenantBackend(csBackend, csTenantB)
	require.NoError(t, err)
	keys, err := b.ListKeys(context.Background())
	require.NoError(t, err)
	require.Len(t, keys, 1)
	keyed, err := b.Seal(context.Background(), []byte(csSecret), &types.SealOptions{KeyAttributes: keys[0]})
	require.NoError(t, err)

	ctxB := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "svc", TenantID: csTenantB})
	defaultKey, err := f.svc.Seal(ctxB, &transport.SealRequest{
		Backend: csBackend, Data: []byte(csSecret), TenantID: csTenantB,
	})
	require.NoError(t, err)
	return csBlobs{keyed: keyed, defaultKey: defaultKey}
}

// requireOthersIntact proves tenant B's and the platform's certificates are
// still stored, byte for byte, where they were seeded.
func (f *csFixture) requireOthersIntact(t *testing.T) {
	t.Helper()
	for _, owner := range []struct{ tenant, id string }{{csTenantB, csBKey}, {"", csSysKey}} {
		b, err := f.svc.LookupTenantBackend(csBackend, owner.tenant)
		require.NoError(t, err)
		got, err := b.GetCert(context.Background(), owner.id)
		require.NoError(t, err, "%s/%s lost its certificate", owner.tenant, owner.id)
		assert.Equal(t, f.certs[owner.tenant+"/"+owner.id].Raw, got.Raw,
			"%s/%s's certificate was replaced", owner.tenant, owner.id)
		chain, err := b.GetCertChain(context.Background(), owner.id)
		require.NoError(t, err, "%s/%s lost its chain", owner.tenant, owner.id)
		require.Len(t, chain, 1)
		assert.Equal(t, f.certs[owner.tenant+"/"+owner.id].Raw, chain[0].Raw,
			"%s/%s's chain was replaced", owner.tenant, owner.id)
	}
}

// csCertPEM returns a fresh certificate as PEM.
func csCertPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pemBytes, err := encoding.EncodeCertificatePEM(generateTestCertificate(t, key))
	require.NoError(t, err)
	return string(pemBytes)
}

// csRoute is one certificate handler under test.
type csRoute struct {
	name    string
	method  string
	pattern string
	handler func(*HandlerContext) http.HandlerFunc
	path    func(id string) string
	body    func(t *testing.T) interface{}
}

func csCertRoutes() []csRoute {
	byID := func(suffix string) func(string) string {
		return func(id string) string {
			return "/api/v1/certs/" + url.PathEscape(id) + suffix + "?backend=" + csBackend
		}
	}
	return []csRoute{
		{
			name: "get", method: http.MethodGet, pattern: "/api/v1/certs/{id}",
			handler: func(h *HandlerContext) http.HandlerFunc { return h.GetCertHandler },
			path:    byID(""),
		},
		{
			name: "exists", method: http.MethodHead, pattern: "/api/v1/certs/{id}",
			handler: func(h *HandlerContext) http.HandlerFunc { return h.CertExistsHandler },
			path:    byID(""),
		},
		{
			name: "delete", method: http.MethodDelete, pattern: "/api/v1/certs/{id}",
			handler: func(h *HandlerContext) http.HandlerFunc { return h.DeleteCertHandler },
			path:    byID(""),
		},
		{
			name: "get-chain", method: http.MethodGet, pattern: "/api/v1/certs/{id}/chain",
			handler: func(h *HandlerContext) http.HandlerFunc { return h.GetCertChainHandler },
			path:    byID("/chain"),
		},
		{
			name: "tls", method: http.MethodGet, pattern: "/api/v1/tls/{id}",
			handler: func(h *HandlerContext) http.HandlerFunc { return h.GetTLSCertificateHandler },
			path: func(id string) string {
				return "/api/v1/tls/" + url.PathEscape(id) + "?backend=" + csBackend
			},
		},
		{
			name: "save", method: http.MethodPost, pattern: "/api/v1/certs",
			handler: func(h *HandlerContext) http.HandlerFunc { return h.SaveCertHandler },
			path: func(id string) string {
				return "/api/v1/certs?key_id=" + url.QueryEscape(id) + "&backend=" + csBackend
			},
			body: func(t *testing.T) interface{} { return SaveCertRequest{CertificatePEM: csCertPEM(t)} },
		},
		{
			name: "save-chain", method: http.MethodPost, pattern: "/api/v1/certs/{id}/chain",
			handler: func(h *HandlerContext) http.HandlerFunc { return h.SaveCertChainHandler },
			path:    byID("/chain"),
			body: func(t *testing.T) interface{} {
				return SaveCertChainRequest{CertChainPEM: []string{csCertPEM(t)}}
			},
		},
	}
}

// csTargets are the IDs tenant A uses to name state it does not own.
var csTargets = []string{csBKey, csTenantB + "/" + csBKey, csSysKey}

// serve runs route as tenant A against f with id and returns the recorder.
func (r csRoute) serve(t *testing.T, f *csFixture, id string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	createRouterWithHandler(r.method, r.pattern, r.handler(f.h)).
		ServeHTTP(w, tenantIdentityRequest(t, r.method, r.path(id), body, csTenantA))
	return w
}

// TestCertHandlers_CrossTenantEqualsGenuineMiss is the go-xkms#1228
// regression for the REST certificate handlers. For every handler and every
// way of naming another owner's certificate, tenant A's response must equal
// its response in a deployment where that certificate does not exist, and
// the other owners' certificates must survive.
func TestCertHandlers_CrossTenantEqualsGenuineMiss(t *testing.T) {
	for _, route := range csCertRoutes() {
		for _, id := range csTargets {
			t.Run(route.name+"/"+id, func(t *testing.T) {
				var body interface{}
				if route.body != nil {
					body = route.body(t)
				}

				full := newCSFixture(t, true)
				cross := route.serve(t, full, id, body)
				full.requireOthersIntact(t)

				miss := route.serve(t, newCSFixture(t, false), id, body)
				assert.Equal(t, miss.Code, cross.Code,
					"tenant A reached another owner's certificate: %s", cross.Body.String())
				assert.Equal(t, miss.Body.String(), cross.Body.String(),
					"a cross-tenant refusal must be indistinguishable from a genuine miss")
			})
		}
	}
}

// TestListCertsHandler_ShowsOnlyTheCallersCerts proves a tenant listing the
// certificate store sees its own certificate, under the ID it used, and
// nothing belonging to another tenant or the platform.
func TestListCertsHandler_ShowsOnlyTheCallersCerts(t *testing.T) {
	f := newCSFixture(t, true)
	w := httptest.NewRecorder()
	createRouterWithHandler(http.MethodGet, "/api/v1/certs", f.h.ListCertsHandler).
		ServeHTTP(w, tenantIdentityRequest(t, http.MethodGet, "/api/v1/certs?backend="+csBackend, nil, csTenantA))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var resp ListCertsResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	ids := make([]string, 0, len(resp.Certificates))
	for _, c := range resp.Certificates {
		ids = append(ids, c.KeyID)
	}
	assert.Equal(t, []string{csAKey}, ids)
	assert.Equal(t, 1, resp.Pagination.Total, "the total must not count another owner's certificates")
}

// TestCertHandlers_OwnCertStillReachable is the positive control: the read
// handlers, naming tenant A's own certificate, succeed.
func TestCertHandlers_OwnCertStillReachable(t *testing.T) {
	for _, route := range csCertRoutes() {
		if route.body != nil || route.method == http.MethodDelete {
			continue
		}
		t.Run(route.name, func(t *testing.T) {
			w := route.serve(t, newCSFixture(t, true), csAKey, nil)
			assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
		})
	}
}

// TestSaveCertHandler_LandsInTheCallersTenant proves a certificate a tenant
// saves is stored in that tenant's namespace, visible to it and to no one
// else, even when it reuses an ID another owner holds.
func TestSaveCertHandler_LandsInTheCallersTenant(t *testing.T) {
	f := newCSFixture(t, true)
	route := csCertRoutes()[5]
	require.Equal(t, "save", route.name)
	w := route.serve(t, f, csSysKey, route.body(t))
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	a, err := f.svc.LookupTenantBackend(csBackend, csTenantA)
	require.NoError(t, err)
	ids, err := a.ListCerts(context.Background())
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{csAKey, csSysKey}, ids)
	f.requireOthersIntact(t)
}

// csSealRequest and csUnsealRequest build tenant A's seal and unseal
// requests.
func csSealRequest(t *testing.T, keyID string) *http.Request {
	return tenantIdentityRequest(t, http.MethodPost, "/api/v1/seal",
		SealRequest{Backend: csBackend, KeyID: keyID, Data: []byte("tenant a's data")}, csTenantA)
}

func csUnsealRequest(t *testing.T, keyID string, blob csBlob) *http.Request {
	return tenantIdentityRequest(t, http.MethodPost, "/api/v1/unseal", UnsealRequest{
		Backend: csBackend, KeyID: keyID,
		Ciphertext: blob.ciphertext, Nonce: blob.nonce, Tag: blob.tag,
	}, csTenantA)
}

// csBlob is the wire half of a sealed blob.
type csBlob struct{ ciphertext, nonce, tag []byte }

func (b csBlobs) keyedBlob() csBlob {
	return csBlob{b.keyed.Ciphertext, b.keyed.Nonce, b.keyed.Tag}
}

func (b csBlobs) defaultBlob() csBlob {
	return csBlob{b.defaultKey.Ciphertext, b.defaultKey.Nonce, b.defaultKey.Tag}
}

// TestSealHandlers_CrossTenantEqualsGenuineMiss is the go-xkms#1228
// regression for REST seal and unseal. Tenant A names B's key or the
// platform's key to seal, and presents B's blobs -- under B's key and under
// the default sealing key -- to unseal. Each answer must equal the answer
// in a deployment where neither the key nor B's sealing state exists.
func TestSealHandlers_CrossTenantEqualsGenuineMiss(t *testing.T) {
	type call func(t *testing.T, f *csFixture, blobs csBlobs) *httptest.ResponseRecorder
	serve := func(pattern string, handler func(*HandlerContext) http.HandlerFunc, req func(*testing.T, csBlobs) *http.Request) call {
		return func(t *testing.T, f *csFixture, blobs csBlobs) *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			createRouterWithHandler(http.MethodPost, pattern, handler(f.h)).ServeHTTP(w, req(t, blobs))
			return w
		}
	}
	seal := func(h *HandlerContext) http.HandlerFunc { return h.SealHandler }
	unseal := func(h *HandlerContext) http.HandlerFunc { return h.UnsealHandler }

	cases := map[string]call{}
	for _, id := range []string{csBKey, csSysKey} {
		cases["seal/"+id] = serve("/api/v1/seal", seal, func(t *testing.T, _ csBlobs) *http.Request {
			return csSealRequest(t, id)
		})
		cases["unseal-keyed/"+id] = serve("/api/v1/unseal", unseal, func(t *testing.T, b csBlobs) *http.Request {
			return csUnsealRequest(t, id, b.keyedBlob())
		})
	}
	cases["unseal-default-key"] = serve("/api/v1/unseal", unseal, func(t *testing.T, b csBlobs) *http.Request {
		return csUnsealRequest(t, "", b.defaultBlob())
	})

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			full := newCSFixture(t, true)
			blobs := full.sealAsB(t)
			cross := c(t, full, blobs)
			assert.NotContains(t, cross.Body.String(), base64.StdEncoding.EncodeToString([]byte(csSecret)),
				"tenant A recovered tenant B's plaintext")

			miss := c(t, newCSFixture(t, false), blobs)
			assert.Equal(t, miss.Code, cross.Code, "tenant A reached another owner's sealing state: %s", cross.Body.String())
			assert.Equal(t, miss.Body.String(), cross.Body.String(),
				"a cross-tenant refusal must be indistinguishable from a genuine miss")
			assert.GreaterOrEqual(t, cross.Code, http.StatusBadRequest, cross.Body.String())
		})
	}
}

// TestSealHandlers_OwnRoundTrip is the positive control: tenant A seals and
// unseals its own data, under its own key and under its default sealing key.
func TestSealHandlers_OwnRoundTrip(t *testing.T) {
	for _, keyID := range []string{csAKey, ""} {
		t.Run("key="+keyID, func(t *testing.T) {
			f := newCSFixture(t, true)
			w := httptest.NewRecorder()
			createRouterWithHandler(http.MethodPost, "/api/v1/seal", f.h.SealHandler).ServeHTTP(w, csSealRequest(t, keyID))
			require.Equal(t, http.StatusOK, w.Code, w.Body.String())
			var sealed SealResponse
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &sealed))

			w = httptest.NewRecorder()
			createRouterWithHandler(http.MethodPost, "/api/v1/unseal", f.h.UnsealHandler).ServeHTTP(w,
				csUnsealRequest(t, keyID, csBlob{sealed.Ciphertext, sealed.Nonce, sealed.Tag}))
			require.Equal(t, http.StatusOK, w.Code, w.Body.String())
			var opened UnsealResponse
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &opened))
			assert.Equal(t, []byte("tenant a's data"), opened.Plaintext)
		})
	}
}
