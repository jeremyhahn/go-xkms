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

// Package keyops_parity_test proves that operations reachable over more than
// one transport return equivalent results, most of it the five
// hardware-capability key operations plus (go-xkms#691) PCR policy
// management.
//
// The key operations were, until recently, reachable only over gRPC and the
// Unix socket; PCR policy management was REST-only, and briefly broken there
// too (see policy_parity_test.go). Adding either to a transport that lacked
// it is only worth anything if the answers actually agree, so this package
// drives one shared xkms service layer through two independent transports
// and compares the wire results field-by-field. It lives in its own package
// because a single test cannot import both pkg/api/rest and pkg/api/grpc
// from inside either one.
package keyops_parity_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	grpcapi "github.com/jeremyhahn/go-xkms/pkg/api/grpc"
	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	restapi "github.com/jeremyhahn/go-xkms/pkg/api/rest"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// =========================================================================
// A key provider carrying the hardware capabilities the five operations need.
// =========================================================================

type attestingProvider struct {
	keys map[string]*types.KeyAttributes

	statement *attestation.AttestationStatement

	// nonce records the nonce the provider was asked to attest over, proving
	// each transport threads the caller's challenge all the way down.
	nonce []byte

	// ecdhPeer and ecdhParams record what DeriveKeyECDH was handed, so a test
	// can assert exactly which KDF parameters each transport delivered. The
	// Label in particular is what gives an ECDH derivation its domain
	// separation: without it, two protocols deriving from the same shared
	// secret and Context produce the same key.
	ecdhPeer   []byte
	ecdhParams *types.KDFParams
}

func newAttestingProvider() *attestingProvider {
	return &attestingProvider{keys: make(map[string]*types.KeyAttributes)}
}

func (p *attestingProvider) addKey(attrs *types.KeyAttributes) { p.keys[attrs.CN] = attrs }

func (p *attestingProvider) Type() types.BackendType { return "attesting" }

func (p *attestingProvider) Capabilities() types.Capabilities {
	return types.Capabilities{Keys: true}
}

func (p *attestingProvider) GenerateKey(_ context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	p.keys[attrs.CN] = attrs
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func (p *attestingProvider) GetKey(_ context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if _, ok := p.keys[attrs.CN]; !ok {
		return nil, errors.New("key not found")
	}
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func (p *attestingProvider) DeleteKey(_ context.Context, attrs *types.KeyAttributes) error {
	delete(p.keys, attrs.CN)
	return nil
}

func (p *attestingProvider) ListKeys(_ context.Context) ([]*types.KeyAttributes, error) {
	attrs := make([]*types.KeyAttributes, 0, len(p.keys))
	for _, a := range p.keys {
		attrs = append(attrs, a)
	}
	return attrs, nil
}

func (p *attestingProvider) Signer(_ context.Context, _ *types.KeyAttributes) (crypto.Signer, error) {
	return nil, errors.New("not supported")
}

func (p *attestingProvider) Decrypter(_ context.Context, _ *types.KeyAttributes) (crypto.Decrypter, error) {
	return nil, errors.New("not supported")
}

func (p *attestingProvider) RotateKey(_ context.Context, _ *types.KeyAttributes) error { return nil }

func (p *attestingProvider) Close() error { return nil }

// AttestKey implements types.AttestingKeyProvider.
func (p *attestingProvider) AttestKey(_ context.Context, _ *types.KeyAttributes, nonce []byte) (interface{}, error) {
	p.nonce = nonce
	return p.statement, nil
}

var _ types.AttestingKeyProvider = (*attestingProvider)(nil)

// bareProvider carries no hardware capability, so it drives the
// capability-boundary half of the parity check.
type bareProvider struct {
	keys map[string]*types.KeyAttributes
}

func newBareProvider() types.KeyProvider {
	return &bareProvider{keys: make(map[string]*types.KeyAttributes)}
}

func (p *bareProvider) Type() types.BackendType          { return "bare" }
func (p *bareProvider) Capabilities() types.Capabilities { return types.Capabilities{Keys: true} }
func (p *bareProvider) GenerateKey(_ context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	p.keys[attrs.CN] = attrs
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}
func (p *bareProvider) GetKey(_ context.Context, _ *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, errors.New("key not found")
}
func (p *bareProvider) DeleteKey(_ context.Context, _ *types.KeyAttributes) error { return nil }
func (p *bareProvider) ListKeys(_ context.Context) ([]*types.KeyAttributes, error) {
	attrs := make([]*types.KeyAttributes, 0, len(p.keys))
	for _, a := range p.keys {
		attrs = append(attrs, a)
	}
	return attrs, nil
}
func (p *bareProvider) Signer(_ context.Context, _ *types.KeyAttributes) (crypto.Signer, error) {
	return nil, errors.New("not supported")
}
func (p *bareProvider) Decrypter(_ context.Context, _ *types.KeyAttributes) (crypto.Decrypter, error) {
	return nil, errors.New("not supported")
}
func (p *bareProvider) RotateKey(_ context.Context, _ *types.KeyAttributes) error { return nil }
func (p *bareProvider) Close() error                                              { return nil }

// =========================================================================
// Shared fixture
// =========================================================================

const (
	attestKeyID  = "idevid"
	hardwareName = "hardware"
	softwareName = "software"
)

// testCert builds a self-signed certificate to stand in for an attestation
// certificate chain, so the parity check covers a []byte-of-DER field and not
// just scalars.
func testCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{CommonName: attestKeyID},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// setupService initialises one xkms service holding an attesting "hardware"
// backend and a capability-free "software" backend. Both transports under test
// are then built over this single service, so any difference in their answers
// is a transport-layer difference and nothing else.
func setupService(t *testing.T) (*xkms.XKMSService, *attestingProvider, *x509.Certificate) {
	t.Helper()

	xkms.Reset()
	t.Cleanup(xkms.Reset)

	cert := testCert(t)

	provider := newAttestingProvider()
	provider.statement = &attestation.AttestationStatement{
		Format:             "tpm2",
		CertificateChain:   []*x509.Certificate{cert},
		AttestationData:    []byte("TPM2_Certify"),
		Signature:          []byte("attestation-signature"),
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		Nonce:              []byte("challenge"),
		Backend:            "tpm2",
	}
	provider.addKey(&types.KeyAttributes{CN: attestKeyID, KeyAlgorithm: x509.ECDSA})

	hardware, err := xkms.New(&xkms.BackendConfig{Backend: provider, CertStorage: storage.New()})
	require.NoError(t, err)

	software, err := xkms.New(&xkms.BackendConfig{Backend: newBareProvider(), CertStorage: storage.New()})
	require.NoError(t, err)

	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends: map[string]xkms.Backend{
			hardwareName: hardware,
			softwareName: software,
		},
		DefaultBackend: softwareName,
	}))

	svc, err := xkms.Get()
	require.NoError(t, err)

	return svc, provider, cert
}

// newRESTServer builds a REST server over the shared service and returns its
// HTTP handler. Authentication is explicitly NoOp and RBAC is off: this test's
// subject is result parity, and the authorization wiring is covered by each
// transport's own authz-denied tests.
func newRESTServer(t *testing.T, svc *xkms.XKMSService) http.Handler {
	t.Helper()

	backends := make(map[string]xkms.Backend, len(svc.BackendNames()))
	for _, name := range svc.BackendNames() {
		b, err := svc.LookupBackend(name)
		require.NoError(t, err)
		backends[name] = b
	}

	server, err := restapi.NewServer(&restapi.Config{
		Port:          0,
		Authenticator: auth.NewNoOpAuthenticator(),
		Backends:      backends,
		XKMSService:   svc,
	})
	require.NoError(t, err)

	return server.Handler()
}

// attestOverREST performs an AttestKey call through the REST router and
// returns the decoded response together with the HTTP status.
func attestOverREST(t *testing.T, handler http.Handler, req *transport.AttestKeyRequest) (*transport.AttestKeyResponse, int) {
	t.Helper()

	body, err := json.Marshal(req)
	require.NoError(t, err)

	httpReq := httptest.NewRequest(http.MethodPost, "/api/v1/attest", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, httpReq)

	if w.Code != http.StatusOK {
		return nil, w.Code
	}

	var resp transport.AttestKeyResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	return &resp, w.Code
}

// attestOverGRPC performs the same call through the gRPC service.
func attestOverGRPC(t *testing.T, svc *grpcapi.Service, req *transport.AttestKeyRequest) (*transport.AttestKeyResponse, error) {
	t.Helper()

	resp, err := svc.AttestKey(context.Background(), &pb.AttestKeyRequest{
		Backend: req.Backend,
		KeyId:   req.KeyID,
		Nonce:   req.Nonce,
	})
	if err != nil {
		return nil, err
	}

	return &transport.AttestKeyResponse{
		Format:             resp.Format,
		CertificateChain:   resp.CertificateChain,
		AttestationData:    resp.AttestationData,
		Signature:          resp.Signature,
		SignatureAlgorithm: resp.SignatureAlgorithm,
		Nonce:              resp.Nonce,
		Backend:            resp.Backend,
	}, nil
}

// TestAttestKey_RESTAndGRPCAgree is the evidence behind the transport-parity
// claim: the same AttestKey request, issued against the same service layer
// over two different transports, must produce byte-identical attestation
// evidence. A transport that dropped, re-encoded, or truncated any field of
// the attestation statement would fail here.
func TestAttestKey_RESTAndGRPCAgree(t *testing.T) {
	svc, provider, cert := setupService(t)

	restHandler := newRESTServer(t, svc)
	grpcService := grpcapi.NewService(nil, nil, svc)

	req := &transport.AttestKeyRequest{
		Backend: hardwareName,
		KeyID:   attestKeyID,
		Nonce:   []byte("challenge"),
	}

	restResp, code := attestOverREST(t, restHandler, req)
	require.Equal(t, http.StatusOK, code)
	require.NotNil(t, restResp)
	assert.Equal(t, []byte("challenge"), provider.nonce, "REST must thread the caller's nonce to the backend")

	provider.nonce = nil

	grpcResp, err := attestOverGRPC(t, grpcService, req)
	require.NoError(t, err)
	require.NotNil(t, grpcResp)
	assert.Equal(t, []byte("challenge"), provider.nonce, "gRPC must thread the caller's nonce to the backend")

	// Field-by-field equivalence.
	assert.Equal(t, grpcResp.Format, restResp.Format)
	assert.Equal(t, grpcResp.AttestationData, restResp.AttestationData)
	assert.Equal(t, grpcResp.Signature, restResp.Signature)
	assert.Equal(t, grpcResp.SignatureAlgorithm, restResp.SignatureAlgorithm)
	assert.Equal(t, grpcResp.Nonce, restResp.Nonce)
	assert.Equal(t, grpcResp.Backend, restResp.Backend)
	require.Equal(t, len(grpcResp.CertificateChain), len(restResp.CertificateChain))
	for i := range grpcResp.CertificateChain {
		assert.Equal(t, grpcResp.CertificateChain[i], restResp.CertificateChain[i])
	}

	// The whole struct must match, so a field added later without transport
	// support is caught here rather than silently diverging.
	assert.Equal(t, grpcResp, restResp)

	// And the evidence must be the backend's, not a transport's invention.
	assert.Equal(t, "tpm2", restResp.Format)
	assert.Equal(t, "tpm2", restResp.Backend)
	assert.Equal(t, x509.ECDSAWithSHA256.String(), restResp.SignatureAlgorithm)
	require.Len(t, restResp.CertificateChain, 1)
	assert.Equal(t, cert.Raw, restResp.CertificateChain[0])
}

// TestAttestKey_CapabilityBoundaryAgrees proves the two transports also agree
// on the negative case: a backend that cannot attest is an "unimplemented"
// answer on both, expressed in each transport's own status vocabulary
// (HTTP 501 / gRPC Unimplemented) rather than one reporting a server fault.
func TestAttestKey_CapabilityBoundaryAgrees(t *testing.T) {
	svc, _, _ := setupService(t)

	restHandler := newRESTServer(t, svc)
	grpcService := grpcapi.NewService(nil, nil, svc)

	req := &transport.AttestKeyRequest{
		Backend: softwareName, // capability-free provider
		KeyID:   attestKeyID,
		Nonce:   []byte("challenge"),
	}

	_, code := attestOverREST(t, restHandler, req)
	assert.Equal(t, http.StatusNotImplemented, code)

	_, err := attestOverGRPC(t, grpcService, req)
	require.Error(t, err)
	assert.Equal(t, codes.Unimplemented, status.Code(err))
}

// TestAttestKey_UnknownKeyAgrees proves both transports report an unresolved
// key as "not found" rather than an internal fault.
func TestAttestKey_UnknownKeyAgrees(t *testing.T) {
	svc, _, _ := setupService(t)

	restHandler := newRESTServer(t, svc)
	grpcService := grpcapi.NewService(nil, nil, svc)

	req := &transport.AttestKeyRequest{
		Backend: hardwareName,
		KeyID:   "no-such-key",
		Nonce:   []byte("challenge"),
	}

	_, code := attestOverREST(t, restHandler, req)
	assert.Equal(t, http.StatusNotFound, code)

	_, err := attestOverGRPC(t, grpcService, req)
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

// TestAttestKey_ValidationAgrees proves both transports reject a request that
// omits a required field as a client error.
func TestAttestKey_ValidationAgrees(t *testing.T) {
	svc, _, _ := setupService(t)

	restHandler := newRESTServer(t, svc)
	grpcService := grpcapi.NewService(nil, nil, svc)

	req := &transport.AttestKeyRequest{
		Backend: hardwareName, // key_id deliberately omitted
		Nonce:   []byte("challenge"),
	}

	_, code := attestOverREST(t, restHandler, req)
	assert.Equal(t, http.StatusBadRequest, code)

	_, err := attestOverGRPC(t, grpcService, req)
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}
