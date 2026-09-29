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

package grpc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ===========================================================================
// Cross-tenant isolation for the certificate and seal RPCs (go-xkms#1228).
//
// Tenant A, authenticated, names state that belongs to tenant B or to the
// platform: B's certificate (by its bare ID and by B's storage namespace,
// "tenant-b/<id>"), the platform's unprefixed certificate, B's sealing key,
// and blobs B sealed. Every RPC must answer exactly as it answers the same
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

// csFixture is one deployment: the gRPC service, the xkms service behind it,
// and the certificates it was seeded with.
type csFixture struct {
	s     *Service
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

	f := &csFixture{s: NewService(nil, nil, svc), svc: svc, certs: map[string]*x509.Certificate{}}
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

// encodeCertToPEM returns cert as a PEM CERTIFICATE block, the encoding the
// certificate RPCs take and return.
func encodeCertToPEM(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
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

	defaultKey, err := f.svc.Seal(tenantCtx(csTenantB), &transport.SealRequest{
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

// csRPC is one certificate RPC under test, called as tenant A naming id.
type csRPC struct {
	name string
	call func(t *testing.T, s *Service, id string) (interface{}, error)
}

func csCertRPCs() []csRPC {
	ctx := tenantCtx(csTenantA)
	return []csRPC{
		{"get", func(_ *testing.T, s *Service, id string) (interface{}, error) {
			return s.GetCert(ctx, &pb.GetCertRequest{KeyId: id})
		}},
		{"exists", func(_ *testing.T, s *Service, id string) (interface{}, error) {
			return s.CertExists(ctx, &pb.CertExistsRequest{KeyId: id})
		}},
		{"delete", func(_ *testing.T, s *Service, id string) (interface{}, error) {
			return s.DeleteCert(ctx, &pb.DeleteCertRequest{KeyId: id})
		}},
		{"get-chain", func(_ *testing.T, s *Service, id string) (interface{}, error) {
			return s.GetCertChain(ctx, &pb.GetCertChainRequest{KeyId: id})
		}},
		{"tls", func(_ *testing.T, s *Service, id string) (interface{}, error) {
			return s.GetTLSCertificate(ctx, &pb.GetTLSCertificateRequest{KeyId: id, Backend: csBackend})
		}},
		{"save", func(t *testing.T, s *Service, id string) (interface{}, error) {
			return s.SaveCert(ctx, &pb.SaveCertRequest{KeyId: id, CertPem: encodeCertToPEM(csSelfSigned(t))})
		}},
		{"save-chain", func(t *testing.T, s *Service, id string) (interface{}, error) {
			return s.SaveCertChain(ctx, &pb.SaveCertChainRequest{
				KeyId: id, CertChainPem: []string{encodeCertToPEM(csSelfSigned(t))},
			})
		}},
	}
}

// csTargets are the IDs tenant A uses to name state it does not own.
var csTargets = []string{csBKey, csTenantB + "/" + csBKey, csSysKey}

// csOutcome reduces an RPC result to what a caller can observe: the status
// code, the message, and whether a response came back.
type csOutcome struct {
	code    codes.Code
	message string
	resp    string
}

func outcomeOf(resp interface{}, err error) csOutcome {
	st, _ := status.FromError(err)
	out := csOutcome{code: st.Code(), message: st.Message()}
	if err == nil {
		out.resp = normalizeResp(resp)
	}
	return out
}

// normalizeResp renders a response for comparison, dropping fields that
// differ between two equivalent answers only because the fixtures differ:
// the freshly generated certificate PEMs a successful read would return.
func normalizeResp(resp interface{}) string {
	switch r := resp.(type) {
	case *pb.SaveCertResponse:
		return r.String()
	case *pb.SaveCertChainResponse:
		return r.String()
	case *pb.DeleteCertResponse:
		return r.String()
	case *pb.CertExistsResponse:
		return r.String()
	default:
		return "returned certificate material"
	}
}

// TestCertRPCs_CrossTenantEqualsGenuineMiss is the go-xkms#1228 regression
// for the gRPC certificate RPCs. For every RPC and every way of naming
// another owner's certificate, tenant A's outcome must equal its outcome in
// a deployment where that certificate does not exist, and the other owners'
// certificates must survive.
func TestCertRPCs_CrossTenantEqualsGenuineMiss(t *testing.T) {
	for _, rpc := range csCertRPCs() {
		for _, id := range csTargets {
			t.Run(rpc.name+"/"+id, func(t *testing.T) {
				full := newCSFixture(t, true)
				cross := outcomeOf(rpc.call(t, full.s, id))
				full.requireOthersIntact(t)

				miss := outcomeOf(rpc.call(t, newCSFixture(t, false).s, id))
				assert.Equal(t, miss, cross,
					"a cross-tenant refusal must be indistinguishable from a genuine miss")
			})
		}
	}
}

// TestListCerts_ShowsOnlyTheCallersCerts proves a tenant listing the
// certificate store sees its own certificate, under the ID it used, and
// nothing belonging to another tenant or the platform.
func TestListCerts_ShowsOnlyTheCallersCerts(t *testing.T) {
	f := newCSFixture(t, true)
	resp, err := f.s.ListCerts(tenantCtx(csTenantA), &pb.ListCertsRequest{})
	require.NoError(t, err)
	assert.Equal(t, []string{csAKey}, resp.KeyIds)
	assert.Equal(t, int32(1), resp.Total)
}

// TestCertRPCs_OwnCertStillReachable is the positive control: the read RPCs,
// naming tenant A's own certificate, succeed.
func TestCertRPCs_OwnCertStillReachable(t *testing.T) {
	for _, rpc := range csCertRPCs() {
		switch rpc.name {
		case "get", "exists", "get-chain", "tls":
		default:
			continue
		}
		t.Run(rpc.name, func(t *testing.T) {
			resp, err := rpc.call(t, newCSFixture(t, true).s, csAKey)
			require.NoError(t, err)
			if exists, ok := resp.(*pb.CertExistsResponse); ok {
				assert.True(t, exists.Exists)
			}
		})
	}
}

// csSeal and csUnseal call Seal and Unseal as tenant A.
func csSeal(s *Service, keyID string) (*pb.SealResponse, error) {
	return s.Seal(tenantCtx(csTenantA), &pb.SealRequest{
		Backend: csBackend, KeyId: keyID, Data: []byte("tenant a's data"),
	})
}

func csUnseal(s *Service, keyID string, ciphertext, nonce, tag []byte) (*pb.UnsealResponse, error) {
	return s.Unseal(tenantCtx(csTenantA), &pb.UnsealRequest{
		Backend: csBackend, KeyId: keyID, Ciphertext: ciphertext, Nonce: nonce, Tag: tag,
	})
}

// TestSealRPCs_CrossTenantEqualsGenuineMiss is the go-xkms#1228 regression
// for gRPC Seal and Unseal. Tenant A names B's key or the platform's key to
// seal, and presents B's blobs -- under B's key and under the default sealing
// key -- to unseal. Each outcome must be a failure equal to the one in a
// deployment where neither the key nor B's sealing state exists.
func TestSealRPCs_CrossTenantEqualsGenuineMiss(t *testing.T) {
	type call func(s *Service, blobs csBlobs) csOutcome
	cases := map[string]call{}
	for _, id := range []string{csBKey, csSysKey} {
		cases["seal/"+id] = func(s *Service, _ csBlobs) csOutcome {
			resp, err := csSeal(s, id)
			return outcomeOf(resp, err)
		}
		cases["unseal-keyed/"+id] = func(s *Service, b csBlobs) csOutcome {
			resp, err := csUnseal(s, id, b.keyed.Ciphertext, b.keyed.Nonce, b.keyed.Tag)
			if err == nil {
				return csOutcome{resp: string(resp.Plaintext)}
			}
			return outcomeOf(resp, err)
		}
	}
	cases["unseal-default-key"] = func(s *Service, b csBlobs) csOutcome {
		resp, err := csUnseal(s, "", b.defaultKey.Ciphertext, b.defaultKey.Nonce, b.defaultKey.Tag)
		if err == nil {
			return csOutcome{resp: string(resp.Plaintext)}
		}
		return outcomeOf(resp, err)
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			full := newCSFixture(t, true)
			blobs := full.sealAsB(t)
			cross := c(full.s, blobs)
			assert.NotEqual(t, csSecret, cross.resp, "tenant A recovered tenant B's plaintext")
			assert.NotEqual(t, codes.OK, cross.code, "tenant A used another owner's sealing state")

			miss := c(newCSFixture(t, false).s, blobs)
			assert.Equal(t, miss, cross,
				"a cross-tenant refusal must be indistinguishable from a genuine miss")
		})
	}
}

// TestSealRPCs_OwnRoundTrip is the positive control: tenant A seals and
// unseals its own data, under its own key and under its default sealing key.
func TestSealRPCs_OwnRoundTrip(t *testing.T) {
	for _, keyID := range []string{csAKey, ""} {
		t.Run("key="+keyID, func(t *testing.T) {
			f := newCSFixture(t, true)
			sealed, err := csSeal(f.s, keyID)
			require.NoError(t, err)
			opened, err := csUnseal(f.s, keyID, sealed.Ciphertext, sealed.Nonce, sealed.Tag)
			require.NoError(t, err)
			assert.Equal(t, []byte("tenant a's data"), opened.Plaintext)
		})
	}
}
