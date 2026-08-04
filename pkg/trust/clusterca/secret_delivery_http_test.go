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

package clusterca

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// nodeSecretOID is a test material OID.
var nodeSecretOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 3, 99}

// recordingProvider captures the request it was asked to provision for.
type recordingProvider struct {
	got *NodeSecretRequest
}

func (p *recordingProvider) ProvisionFor(_ context.Context, req *NodeSecretRequest) (*ProvisionedSecret, error) {
	p.got = req
	return &ProvisionedSecret{OID: nodeSecretOID, Data: []byte("wrapped")}, nil
}

func certPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// TestSecretDelivery_HTTPRoundTrip exercises the full server handler + client
// fetch: a verified node certificate authorizes the request, the provider runs,
// and the wrapped material round-trips back with the node's SPIFFE identity.
func TestSecretDelivery_HTTPRoundTrip(t *testing.T) {
	const nodeURI = "spiffe://test.cluster/node/10.0.0.2:63001"
	_, intermediate, leaf := miniChain(t, nodeURI)

	// Trust pool: the leaf is signed by the intermediate, so add the
	// intermediate as a trusted root for verification.
	pool := x509.NewCertPool()
	pool.AddCert(intermediate)

	provider := &recordingProvider{}
	svc := NewSecretDeliveryService(nil, pool, provider)
	require.True(t, svc.HasProviders())

	mux := http.NewServeMux()
	mux.HandleFunc(SecretDeliveryPath, svc.Handler())
	server := httptest.NewServer(mux)
	defer server.Close()

	nodeCertPEM := certPEM(leaf.Raw)
	ekCertPEM := certPEM(intermediate.Raw) // any valid cert stands in for the EK
	secrets, err := FetchClusterSecrets(context.Background(), server.Client(), server.URL,
		nodeCertPEM, ekCertPEM, []byte("iak-pub"))
	require.NoError(t, err)
	require.Len(t, secrets, 1)
	require.True(t, secrets[0].OID.Equal(nodeSecretOID))
	require.Equal(t, []byte("wrapped"), secrets[0].Data)

	// The server took the authoritative identity from the node certificate SAN.
	require.NotNil(t, provider.got)
	require.Equal(t, nodeURI, provider.got.NodeURI)
	require.NotNil(t, provider.got.EKCertificate)
}

// TestSecretDelivery_RejectsUntrustedNodeCert verifies a node certificate that
// does not chain to the configured cluster CA is rejected (401).
func TestSecretDelivery_RejectsUntrustedNodeCert(t *testing.T) {
	_, _, leaf := miniChain(t, "spiffe://test.cluster/node/10.0.0.9:1")

	// Trust pool contains an UNRELATED CA, so the leaf does not verify.
	otherRoot, _, _ := miniChain(t, "spiffe://other.cluster/node/1.1.1.1:1")
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(otherRoot))

	svc := NewSecretDeliveryService(nil, pool, &recordingProvider{})
	mux := http.NewServeMux()
	mux.HandleFunc(SecretDeliveryPath, svc.Handler())
	server := httptest.NewServer(mux)
	defer server.Close()

	_, err := FetchClusterSecrets(context.Background(), server.Client(), server.URL,
		certPEM(leaf.Raw), certPEM(leaf.Raw), []byte("iak"))
	require.Error(t, err) // non-200 (401 unauthorized)
}

// TestSecretDelivery_HandlerRejectsBadInput verifies method + malformed-body
// handling.
func TestSecretDelivery_HandlerRejectsBadInput(t *testing.T) {
	svc := NewSecretDeliveryService(nil, nil, &recordingProvider{})
	handler := svc.Handler()

	// Wrong method.
	rec := httptest.NewRecorder()
	handler(rec, httptest.NewRequest(http.MethodGet, SecretDeliveryPath, nil))
	require.Equal(t, http.StatusMethodNotAllowed, rec.Code)

	// Malformed body.
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, SecretDeliveryPath, nil)
	handler(rec, req)
	require.Equal(t, http.StatusBadRequest, rec.Code)
}
