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

package keyops_parity_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	grpcapi "github.com/jeremyhahn/go-xkms/pkg/api/grpc"
	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// parityECDHSecret is a fixed stand-in for the ECDH shared secret, so every
// derivation below depends only on the KDF parameters that reached the backend.
var parityECDHSecret = []byte("fixed-ecdh-shared-secret-32bytes")

// DeriveKeyECDH makes the shared fixture's provider a types.KeyAgreementProvider
// that runs the KDF parameters it is handed. Recording them proves what each
// transport delivered; deriving from them proves the parameters are actually
// bound into the key rather than carried alongside it.
func (p *attestingProvider) DeriveKeyECDH(_ context.Context, _ *types.KeyAttributes, peer []byte, params *types.KDFParams) ([]byte, error) {
	p.ecdhPeer = peer
	p.ecdhParams = params
	return params.Derive(parityECDHSecret)
}

func (p *attestingProvider) SupportedCurves() []string { return []string{"P-256", "P-384"} }

var _ types.KeyAgreementProvider = (*attestingProvider)(nil)

// deriveECDHOverREST issues a DeriveKeyECDH through the REST router.
func deriveECDHOverREST(t *testing.T, handler http.Handler, req *transport.DeriveKeyECDHRequest) (*transport.DeriveKeyECDHResponse, int) {
	t.Helper()

	body, err := json.Marshal(req)
	require.NoError(t, err)

	httpReq := httptest.NewRequest(http.MethodPost, "/api/v1/keys/derive-ecdh", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, httpReq)

	if w.Code != http.StatusOK {
		return nil, w.Code
	}

	var resp transport.DeriveKeyECDHResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	return &resp, w.Code
}

// deriveECDHOverGRPC issues the same call through the gRPC service, which is
// also the service the Unix socket server registers.
func deriveECDHOverGRPC(t *testing.T, svc *grpcapi.Service, req *transport.DeriveKeyECDHRequest) (*transport.DeriveKeyECDHResponse, error) {
	t.Helper()

	resp, err := svc.DeriveKeyECDH(context.Background(), &pb.DeriveKeyECDHRequest{
		KeyId:         req.KeyID,
		Backend:       req.Backend,
		PeerPublicKey: req.PeerPublicKey,
		KdfAlgorithm:  req.KDFAlgorithm,
		KdfHash:       req.KDFHash,
		KdfSalt:       req.KDFSalt,
		KdfInfo:       req.KDFInfo,
		KdfLabel:      req.KDFLabel,
		KeyLength:     int32(req.KeyLength),
	})
	if err != nil {
		return nil, err
	}
	return &transport.DeriveKeyECDHResponse{DerivedKey: resp.DerivedKey}, nil
}

func parityECDHRequest() *transport.DeriveKeyECDHRequest {
	return &transport.DeriveKeyECDHRequest{
		KeyID:         attestKeyID,
		Backend:       hardwareName,
		PeerPublicKey: []byte("peer-public-key"),
		KDFAlgorithm:  "SP800-108-COUNTER",
		KDFHash:       "SHA-256",
		KDFInfo:       []byte("shared-context"),
		KeyLength:     32,
	}
}

// TestDeriveKeyECDH_LabelReachesEveryTransport proves the SP 800-108 label
// survives both wire encodings — JSON on REST, protobuf on gRPC and the Unix
// socket — and lands on the same KDF input on both. A transport that dropped
// the field would derive a key without domain separation and report success.
func TestDeriveKeyECDH_LabelReachesEveryTransport(t *testing.T) {
	svc, provider, _ := setupService(t)

	restHandler := newRESTServer(t, svc)
	grpcService := grpcapi.NewService(nil, nil, svc)

	req := parityECDHRequest()
	req.KDFLabel = []byte("tls-exporter")

	restResp, code := deriveECDHOverREST(t, restHandler, req)
	require.Equal(t, http.StatusOK, code)
	require.NotNil(t, restResp)
	require.NotNil(t, provider.ecdhParams)
	assert.Equal(t, []byte("tls-exporter"), provider.ecdhParams.Label, "REST must thread the label to the KDF")

	provider.ecdhParams = nil

	grpcResp, err := deriveECDHOverGRPC(t, grpcService, req)
	require.NoError(t, err)
	require.NotNil(t, grpcResp)
	require.NotNil(t, provider.ecdhParams)
	assert.Equal(t, []byte("tls-exporter"), provider.ecdhParams.Label, "gRPC must thread the label to the KDF")

	assert.Equal(t, grpcResp.DerivedKey, restResp.DerivedKey,
		"both transports must derive the same key from the same parameters")

	// The key must be the one the label actually produces.
	want, err := (&types.KDFParams{
		Algorithm: types.KDFAlgorithmSP800108Counter,
		Hash:      "SHA-256",
		Label:     []byte("tls-exporter"),
		Context:   []byte("shared-context"),
		KeyLength: 32,
	}).Derive(parityECDHSecret)
	require.NoError(t, err)
	assert.Equal(t, want, restResp.DerivedKey)
}

// TestDeriveKeyECDH_LabelSeparatesDomainsOnEveryTransport asserts the field
// does the job it was added for on both transports: same secret, same context,
// different label, different key.
func TestDeriveKeyECDH_LabelSeparatesDomainsOnEveryTransport(t *testing.T) {
	svc, _, _ := setupService(t)

	restHandler := newRESTServer(t, svc)
	grpcService := grpcapi.NewService(nil, nil, svc)

	protocolA := parityECDHRequest()
	protocolA.KDFLabel = []byte("protocol-a")
	protocolB := parityECDHRequest()
	protocolB.KDFLabel = []byte("protocol-b")

	restA, code := deriveECDHOverREST(t, restHandler, protocolA)
	require.Equal(t, http.StatusOK, code)
	restB, code := deriveECDHOverREST(t, restHandler, protocolB)
	require.Equal(t, http.StatusOK, code)
	assert.NotEqual(t, restA.DerivedKey, restB.DerivedKey)

	grpcA, err := deriveECDHOverGRPC(t, grpcService, protocolA)
	require.NoError(t, err)
	grpcB, err := deriveECDHOverGRPC(t, grpcService, protocolB)
	require.NoError(t, err)
	assert.NotEqual(t, grpcA.DerivedKey, grpcB.DerivedKey)

	// Cross-transport: the same label agrees, different labels disagree.
	assert.Equal(t, restA.DerivedKey, grpcA.DerivedKey)
	assert.Equal(t, restB.DerivedKey, grpcB.DerivedKey)
	assert.NotEqual(t, restA.DerivedKey, grpcB.DerivedKey)
}

// TestDeriveKeyECDH_AbsentLabelIsUnchangedOnEveryTransport is the compatibility
// half: a request that omits the label must derive exactly what it derived
// before the field existed, on every transport.
func TestDeriveKeyECDH_AbsentLabelIsUnchangedOnEveryTransport(t *testing.T) {
	svc, provider, _ := setupService(t)

	restHandler := newRESTServer(t, svc)
	grpcService := grpcapi.NewService(nil, nil, svc)

	req := parityECDHRequest() // no KDFLabel

	restResp, code := deriveECDHOverREST(t, restHandler, req)
	require.Equal(t, http.StatusOK, code)
	require.NotNil(t, provider.ecdhParams)
	assert.Empty(t, provider.ecdhParams.Label, "an absent label must not be invented")

	grpcResp, err := deriveECDHOverGRPC(t, grpcService, req)
	require.NoError(t, err)
	require.NotNil(t, provider.ecdhParams)
	assert.Empty(t, provider.ecdhParams.Label)

	want, err := (&types.KDFParams{
		Algorithm: types.KDFAlgorithmSP800108Counter,
		Hash:      "SHA-256",
		Context:   []byte("shared-context"),
		KeyLength: 32,
	}).Derive(parityECDHSecret)
	require.NoError(t, err)

	assert.Equal(t, want, restResp.DerivedKey)
	assert.Equal(t, want, grpcResp.DerivedKey)
	assert.Equal(t, "575ccf15320e43089258d904470dd2bf32f78cf6dfb912a4a26f2f785dc3fc6c",
		hexString(restResp.DerivedKey), "the no-label derivation must not move")
}

// TestDeriveKeyECDH_LabelRejectionAgrees proves both transports refuse a label
// supplied to a construction that has no label input, in their own status
// vocabulary, rather than one of them silently dropping it.
func TestDeriveKeyECDH_LabelRejectionAgrees(t *testing.T) {
	svc, _, _ := setupService(t)

	restHandler := newRESTServer(t, svc)
	grpcService := grpcapi.NewService(nil, nil, svc)

	for _, algorithm := range []string{"HKDF", "X963", "SP800-56A"} {
		t.Run(algorithm, func(t *testing.T) {
			req := parityECDHRequest()
			req.KDFAlgorithm = algorithm
			req.KDFLabel = []byte("no-home-here")

			_, code := deriveECDHOverREST(t, restHandler, req)
			assert.Equal(t, http.StatusBadRequest, code)

			_, err := deriveECDHOverGRPC(t, grpcService, req)
			require.Error(t, err)
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
		})
	}
}

// TestDeriveKeyECDH_UnknownKDFAlgorithmAgrees proves both transports refuse an
// unrecognized KDF name rather than answering it with HKDF keying material.
func TestDeriveKeyECDH_UnknownKDFAlgorithmAgrees(t *testing.T) {
	svc, provider, _ := setupService(t)

	restHandler := newRESTServer(t, svc)
	grpcService := grpcapi.NewService(nil, nil, svc)

	req := parityECDHRequest()
	req.KDFAlgorithm = "SP800-108-COUNTR"

	_, code := deriveECDHOverREST(t, restHandler, req)
	assert.Equal(t, http.StatusBadRequest, code)

	_, err := deriveECDHOverGRPC(t, grpcService, req)
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	assert.Nil(t, provider.ecdhParams, "a refused algorithm must never reach the KDF")
}

// hexString renders derived key material for golden-vector assertions. The
// vectors are what make a KDF-parameter regression visible: two derivations
// that both "succeed" but produce different bytes are otherwise indistinguishable
// from correct behaviour.
func hexString(b []byte) string { return hex.EncodeToString(b) }
