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

package mcp

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/peergate"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
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

// createPeerAttestationServer returns a test server whose service collects
// peer evidence into the returned recorder.
func createPeerAttestationServer(t *testing.T) (*Server, *peerEvidenceRecorder) {
	t.Helper()
	s := createTestServer(t)
	store := &peerEvidenceRecorder{records: make(map[string]peergate.Record)}
	collector, err := peergate.NewCollector(peergate.CollectorConfig{Store: store})
	require.NoError(t, err)
	s.xkmsService.SetPeerEvidenceCollector(collector)
	return s, store
}

// mutualTLSState returns the server's view of an mTLS connection, as
// go-qrdb's MCP transport puts it on the context.
func mutualTLSState(t *testing.T) *tls.ConnectionState {
	t.Helper()
	state, err := testutil.MutualTLSState()
	require.NoError(t, err)
	return state
}

// invokePeerAttestation calls method as an authenticated caller over a
// connection with the given TLS state (none when nil) and decodes the result
// into out.
func invokePeerAttestation(t *testing.T, s *Server, state *tls.ConnectionState, method string, params json.RawMessage, out any) error {
	t.Helper()
	ctx := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "peer", TenantID: "acme", Roles: []string{"admin"}})
	if state != nil {
		ctx = auth.WithTLSState(ctx, state)
	}
	result, err := s.InvokeMethod(ctx, method, params)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(result)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(encoded, out))
	return nil
}

// TestPeerAttestationTools_ChallengeThenSubmit proves the methods reach the
// collector: the challenge issues a nonce to the caller's certificate, the
// evidence answering it is stored, and a second answer is refused.
func TestPeerAttestationTools_ChallengeThenSubmit(t *testing.T) {
	s, store := createPeerAttestationServer(t)
	state := mutualTLSState(t)

	var challenge transport.PeerAttestationChallenge
	require.NoError(t, invokePeerAttestation(t, s, state, "peer.attestation.challenge", nil, &challenge))
	require.Len(t, challenge.Nonce, peergate.NonceLength)

	evidence, err := json.Marshal(transport.SubmitPeerAttestationRequest{
		Quote:            []byte("quote"),
		Signature:        []byte("signature"),
		Nonce:            challenge.Nonce,
		PCRs:             map[int][]byte{7: make([]byte, 32)},
		AKCertificatePEM: []byte("ak"),
	})
	require.NoError(t, err)
	var empty map[string]any
	require.NoError(t, invokePeerAttestation(t, s, state, "peer.attestation.submit", evidence, &empty))
	assert.Empty(t, empty)
	assert.Equal(t, 1, store.len())

	err = invokePeerAttestation(t, s, state, "peer.attestation.submit", evidence, &empty)
	var keyErr *KeyOpError
	require.ErrorAs(t, err, &keyErr, "a challenge answers once")
	assert.Equal(t, ErrCodeInternalError, keyErr.Code)
}

// TestPeerAttestationTools_MapsErrors proves each refusal reaches the wire
// with the code apierrors.PeerAttestationClassOf's class maps to.
func TestPeerAttestationTools_MapsErrors(t *testing.T) {
	gated, store := createPeerAttestationServer(t)
	tests := []struct {
		name, method string
		params       json.RawMessage
		code         int
	}{
		{"challenge without a client certificate", "peer.attestation.challenge", nil, ErrCodeInvalidParams},
		{"submit without a client certificate", "peer.attestation.submit", json.RawMessage(`{"nonce":"AA=="}`), ErrCodeInvalidParams},
		{"malformed submit", "peer.attestation.submit", json.RawMessage(`"evidence"`), ErrCodeInvalidParams},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out map[string]any
			err := invokePeerAttestation(t, gated, nil, tt.method, tt.params, &out)
			var keyErr *KeyOpError
			require.ErrorAs(t, err, &keyErr)
			assert.Equal(t, tt.code, keyErr.Code)
		})
	}
	assert.Zero(t, store.len())
}

// TestPeerAttestationTools_WithoutTheGate proves a server whose node runs no
// attested-caller gate answers both methods as unavailable.
func TestPeerAttestationTools_WithoutTheGate(t *testing.T) {
	s := createTestServer(t)
	state := mutualTLSState(t)
	for _, method := range []string{"peer.attestation.challenge", "peer.attestation.submit"} {
		t.Run(method, func(t *testing.T) {
			var out map[string]any
			err := invokePeerAttestation(t, s, state, method, json.RawMessage(`{}`), &out)
			var keyErr *KeyOpError
			require.ErrorAs(t, err, &keyErr)
			assert.Equal(t, ErrCodeServiceUnavailable, keyErr.Code)
		})
	}
}
