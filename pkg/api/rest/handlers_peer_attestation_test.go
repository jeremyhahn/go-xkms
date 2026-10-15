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
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/peergate"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// peerEvidenceRecorder keeps the collector's records in memory so the tests
// can see what a submission stored.
type peerEvidenceRecorder struct {
	mu      sync.Mutex
	records map[string]peergate.Record
}

func (s *peerEvidenceRecorder) Put(_ context.Context, r peergate.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[r.Thumbprint] = r
	return nil
}

func (s *peerEvidenceRecorder) Get(_ context.Context, thumbprint string) (peergate.Record, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[thumbprint]
	return r, ok, nil
}

func (s *peerEvidenceRecorder) Delete(_ context.Context, thumbprint string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.records, thumbprint)
	return nil
}

func (s *peerEvidenceRecorder) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.records)
}

// peerAttestationRouter mounts the peer_attestation routes, as Routes()
// registers them, over svc.
func peerAttestationRouter(svc *xkms.XKMSService) http.Handler {
	server := &Server{peerAttestationHandlers: NewPeerAttestationHandlers(svc)}
	r := chi.NewRouter()
	for _, spec := range Routes() {
		if spec.Resource == auth.ResourcePeerAttestation {
			r.Method(spec.Method, spec.Pattern, spec.Handler(server))
		}
	}
	return r
}

// newPeerAttestationService returns a service whose collector writes to the
// returned recorder.
func newPeerAttestationService(t *testing.T) (*xkms.XKMSService, *peerEvidenceRecorder) {
	t.Helper()
	store := &peerEvidenceRecorder{records: make(map[string]peergate.Record)}
	collector, err := peergate.NewCollector(peergate.CollectorConfig{Store: store})
	require.NoError(t, err)
	svc := &xkms.XKMSService{}
	svc.SetPeerEvidenceCollector(collector)
	return svc, store
}

// newMutualTLSServer serves handler over TLS 1.3 requiring a client
// certificate from a test CA, and returns a client presenting one.
func newMutualTLSServer(t *testing.T, handler http.Handler) (*httptest.Server, *http.Client) {
	t.Helper()
	ca, err := testutil.GenerateTestCA()
	require.NoError(t, err)
	serverCert, err := testutil.GenerateTestServerCert(ca, "localhost")
	require.NoError(t, err)
	clientCert, err := testutil.GenerateTestClientCert(ca, "peer")
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)

	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert.TLSCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS13,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		Certificates: []tls.Certificate{clientCert.TLSCert},
		RootCAs:      pool,
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS13,
	}}}
	t.Cleanup(client.CloseIdleConnections)
	return srv, client
}

func postJSON(t *testing.T, client *http.Client, url string, body []byte) *http.Response {
	t.Helper()
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, resp.Body.Close()) })
	return resp
}

// TestPeerAttestationREST_ChallengeThenEvidence proves the routes reach the
// collector over mutual TLS: the challenge issues a nonce to the client
// certificate, the evidence answering it is stored, and a second answer to
// the same challenge is refused as the connection's state, 409.
func TestPeerAttestationREST_ChallengeThenEvidence(t *testing.T) {
	svc, store := newPeerAttestationService(t)
	srv, client := newMutualTLSServer(t, peerAttestationRouter(svc))

	resp := postJSON(t, client, srv.URL+"/api/v1/peer-attestation/challenge", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var challenge transport.PeerAttestationChallenge
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&challenge))
	require.Len(t, challenge.Nonce, peergate.NonceLength)

	evidence, err := json.Marshal(transport.SubmitPeerAttestationRequest{
		Quote:            []byte("quote"),
		Signature:        []byte("signature"),
		Nonce:            challenge.Nonce,
		PCRs:             map[int][]byte{7: make([]byte, 32)},
		AKCertificatePEM: []byte("ak"),
	})
	require.NoError(t, err)
	resp = postJSON(t, client, srv.URL+"/api/v1/peer-attestation/evidence", evidence)
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
	assert.Equal(t, 1, store.len())

	resp = postJSON(t, client, srv.URL+"/api/v1/peer-attestation/evidence", evidence)
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "a challenge answers once")
}

// TestPeerAttestationREST_MapsErrors proves each refusal reaches the wire
// with the status apierrors.PeerAttestationClassOf's class maps to.
func TestPeerAttestationREST_MapsErrors(t *testing.T) {
	gated, store := newPeerAttestationService(t)
	tests := []struct {
		name, path, body string
		svc              *xkms.XKMSService
		status           int
	}{
		{"challenge without a client certificate", "/api/v1/peer-attestation/challenge", "", gated, http.StatusUnauthorized},
		{"evidence without a client certificate", "/api/v1/peer-attestation/evidence", `{"nonce":"AA=="}`, gated, http.StatusUnauthorized},
		{"malformed evidence", "/api/v1/peer-attestation/evidence", "{", gated, http.StatusBadRequest},
		{"no gate", "/api/v1/peer-attestation/challenge", "", &xkms.XKMSService{}, http.StatusServiceUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body io.Reader
			if tt.body != "" {
				body = strings.NewReader(tt.body)
			}
			w := httptest.NewRecorder()
			peerAttestationRouter(tt.svc).ServeHTTP(w, httptest.NewRequest(http.MethodPost, tt.path, body))
			assert.Equal(t, tt.status, w.Code, w.Body.String())
		})
	}
	assert.Zero(t, store.len())
}
