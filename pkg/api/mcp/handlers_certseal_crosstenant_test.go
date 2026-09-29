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

package mcp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ===========================================================================
// Cross-tenant isolation for the certificate and seal methods (go-xkms#1228).
//
// Tenant A, authenticated, names state that belongs to tenant B or to the
// platform: B's certificate (by its bare ID and by B's storage namespace,
// "tenant-b/<id>"), the platform's unprefixed certificate, B's sealing key,
// and blobs B sealed. Every method must answer exactly as it answers the same
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

// csFixture is one deployment: the MCP server, the service behind it, and
// the certificates it was seeded with.
type csFixture struct {
	s     *Server
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
// true, tenant B holds the same under csBKey, and the platform holds an
// untenanted key and certificate under csSysKey.
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

	f := &csFixture{s: &Server{xkmsService: svc, keystore: ks}, svc: svc, certs: map[string]*x509.Certificate{}}
	f.seed(t, csTenantA, csAKey)
	if others {
		f.seed(t, csTenantB, csBKey)
		f.seed(t, "", csSysKey)
	}
	return f
}

// csSelfSigned returns a fresh self-signed ECDSA certificate.
func csSelfSigned(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "cross-tenant"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// csCertPEM returns a fresh certificate as PEM.
func csCertPEM(t *testing.T) string {
	t.Helper()
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: csSelfSigned(t).Raw}))
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

	cert := csSelfSigned(t)
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

	defaultKey, err := f.svc.Seal(tenantContext(csTenantB), &transport.SealRequest{
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

// invokeAsA runs method as tenant A and returns the wire response.
func (f *csFixture) invokeAsA(t *testing.T, method string, params interface{}) *JSONRPCResponse {
	t.Helper()
	return invokeRequest(f.s, tenantContext(csTenantA), keyOpsRequest(t, method, params))
}

// csObservable reduces a response to what a caller can compare across two
// deployments: the error, or for a success the result with certificate
// material (which differs between fixtures by construction) marked rather
// than compared.
func csObservable(t *testing.T, resp *JSONRPCResponse) string {
	t.Helper()
	if resp.Error != nil {
		raw, err := json.Marshal(resp.Error)
		require.NoError(t, err)
		return "error:" + string(raw)
	}
	switch resp.Result.(type) {
	case GetCertResult, GetCertChainResult, transport.GetTLSCertificateResponse:
		return "result: certificate material"
	}
	raw, err := json.Marshal(resp.Result)
	require.NoError(t, err)
	return "result:" + string(raw)
}

// csMethod is one certificate method under test.
type csMethod struct {
	name   string
	params func(t *testing.T, id string) interface{}
}

func csCertMethods() []csMethod {
	byID := func(_ *testing.T, id string) interface{} { return map[string]string{"key_id": id} }
	return []csMethod{
		{"xkms.getCert", byID},
		{"xkms.certExists", byID},
		{"xkms.deleteCert", byID},
		{"xkms.getCertChain", byID},
		{"xkms.getTLSCertificate", func(_ *testing.T, id string) interface{} {
			return GetTLSCertificateParams{KeyID: id, Backend: csBackend}
		}},
		{"xkms.saveCert", func(t *testing.T, id string) interface{} {
			return SaveCertParams{KeyID: id, CertPEM: csCertPEM(t)}
		}},
		{"xkms.saveCertChain", func(t *testing.T, id string) interface{} {
			return SaveCertChainParams{KeyID: id, ChainPEMs: []string{csCertPEM(t)}}
		}},
	}
}

// csTargets are the IDs tenant A uses to name state it does not own.
var csTargets = []string{csBKey, csTenantB + "/" + csBKey, csSysKey}

// TestCertMethods_CrossTenantEqualsGenuineMiss is the go-xkms#1228
// regression for the MCP certificate methods. For every method and every way
// of naming another owner's certificate, tenant A's response must equal its
// response in a deployment where that certificate does not exist, and the
// other owners' certificates must survive.
func TestCertMethods_CrossTenantEqualsGenuineMiss(t *testing.T) {
	for _, m := range csCertMethods() {
		for _, id := range csTargets {
			t.Run(m.name+"/"+id, func(t *testing.T) {
				params := m.params(t, id)

				full := newCSFixture(t, true)
				cross := csObservable(t, full.invokeAsA(t, m.name, params))
				full.requireOthersIntact(t)

				miss := csObservable(t, newCSFixture(t, false).invokeAsA(t, m.name, params))
				assert.Equal(t, miss, cross,
					"a cross-tenant refusal must be indistinguishable from a genuine miss")
			})
		}
	}
}

// TestListCertsMethod_ShowsOnlyTheCallersCerts proves a tenant listing the
// certificate store sees its own certificate, under the ID it used, and
// nothing belonging to another tenant or the platform.
func TestListCertsMethod_ShowsOnlyTheCallersCerts(t *testing.T) {
	resp := newCSFixture(t, true).invokeAsA(t, "xkms.listCerts", map[string]string{})
	require.Nil(t, resp.Error)
	result, ok := resp.Result.(ListCertsResult)
	require.True(t, ok, "%T", resp.Result)
	assert.Equal(t, []string{csAKey}, result.KeyIDs)
	require.NotNil(t, result.Pagination)
	assert.Equal(t, 1, result.Pagination.Total)
}

// TestCertMethods_OwnCertStillReachable is the positive control: the read
// methods, naming tenant A's own certificate, succeed.
func TestCertMethods_OwnCertStillReachable(t *testing.T) {
	for _, m := range csCertMethods()[:5] {
		if m.name == "xkms.deleteCert" {
			continue
		}
		t.Run(m.name, func(t *testing.T) {
			resp := newCSFixture(t, true).invokeAsA(t, m.name, m.params(t, csAKey))
			require.Nil(t, resp.Error, "%+v", resp.Error)
			if exists, ok := resp.Result.(CertExistsResult); ok {
				assert.True(t, exists.Exists)
			}
		})
	}
}

// csUnsealParams builds tenant A's unseal params for a blob.
func csUnsealParams(keyID string, ciphertext, nonce, tag []byte) UnsealParams {
	return UnsealParams{Backend: csBackend, KeyID: keyID, Ciphertext: ciphertext, Nonce: nonce, Tag: tag}
}

// TestSealMethods_CrossTenantEqualsGenuineMiss is the go-xkms#1228
// regression for MCP seal and unseal. Tenant A names B's key or the
// platform's key to seal, and presents B's blobs -- under B's key and under
// the default sealing key -- to unseal. Each response must be an error equal
// to the one in a deployment where neither the key nor B's sealing state
// exists.
func TestSealMethods_CrossTenantEqualsGenuineMiss(t *testing.T) {
	type call func(t *testing.T, f *csFixture, blobs csBlobs) *JSONRPCResponse
	cases := map[string]call{}
	for _, id := range []string{csBKey, csSysKey} {
		cases["seal/"+id] = func(t *testing.T, f *csFixture, _ csBlobs) *JSONRPCResponse {
			return f.invokeAsA(t, "xkms.seal", SealParams{Backend: csBackend, KeyID: id, Data: []byte("tenant a's data")})
		}
		cases["unseal-keyed/"+id] = func(t *testing.T, f *csFixture, b csBlobs) *JSONRPCResponse {
			return f.invokeAsA(t, "xkms.unseal", csUnsealParams(id, b.keyed.Ciphertext, b.keyed.Nonce, b.keyed.Tag))
		}
	}
	cases["unseal-default-key"] = func(t *testing.T, f *csFixture, b csBlobs) *JSONRPCResponse {
		return f.invokeAsA(t, "xkms.unseal",
			csUnsealParams("", b.defaultKey.Ciphertext, b.defaultKey.Nonce, b.defaultKey.Tag))
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			full := newCSFixture(t, true)
			blobs := full.sealAsB(t)
			crossResp := c(t, full, blobs)
			require.NotNil(t, crossResp.Error, "tenant A used another owner's sealing state: %+v", crossResp.Result)

			miss := csObservable(t, c(t, newCSFixture(t, false), blobs))
			assert.Equal(t, miss, csObservable(t, crossResp),
				"a cross-tenant refusal must be indistinguishable from a genuine miss")
		})
	}
}

// TestSealMethods_OwnRoundTrip is the positive control: tenant A seals and
// unseals its own data, under its own key and under its default sealing key.
func TestSealMethods_OwnRoundTrip(t *testing.T) {
	for _, keyID := range []string{csAKey, ""} {
		t.Run("key="+keyID, func(t *testing.T) {
			f := newCSFixture(t, true)
			resp := f.invokeAsA(t, "xkms.seal", SealParams{Backend: csBackend, KeyID: keyID, Data: []byte("tenant a's data")})
			require.Nil(t, resp.Error, "%+v", resp.Error)
			sealed, ok := resp.Result.(SealResult)
			require.True(t, ok, "%T", resp.Result)

			resp = f.invokeAsA(t, "xkms.unseal", csUnsealParams(keyID, sealed.Ciphertext, sealed.Nonce, sealed.Tag))
			require.Nil(t, resp.Error, "%+v", resp.Error)
			opened, ok := resp.Result.(UnsealResult)
			require.True(t, ok, "%T", resp.Result)
			assert.Equal(t, []byte("tenant a's data"), opened.Plaintext)
		})
	}
}
