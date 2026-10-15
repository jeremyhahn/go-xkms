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

package xkms

import (
	"context"
	"crypto/tls"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/peergate"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

// recordingEvidenceStore keeps the collector's records in memory so the
// tests can see what a submission stored.
type recordingEvidenceStore struct {
	mu      sync.Mutex
	records map[string]peergate.Record
}

func (s *recordingEvidenceStore) Put(_ context.Context, r peergate.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[r.Thumbprint] = r
	return nil
}

func (s *recordingEvidenceStore) Get(_ context.Context, thumbprint string) (peergate.Record, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[thumbprint]
	return r, ok, nil
}

func (s *recordingEvidenceStore) Delete(_ context.Context, thumbprint string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.records, thumbprint)
	return nil
}

func newPeerAttestationService(t *testing.T) (*XKMSService, *recordingEvidenceStore) {
	t.Helper()
	store := &recordingEvidenceStore{records: make(map[string]peergate.Record)}
	collector, err := peergate.NewCollector(peergate.CollectorConfig{Store: store})
	require.NoError(t, err)
	svc := &XKMSService{}
	svc.SetPeerEvidenceCollector(collector)
	return svc, store
}

// mutualTLSContext returns a context carrying the server's view of an mTLS
// connection, as a transport hands it to the service.
func mutualTLSContext(t *testing.T) context.Context {
	t.Helper()
	state, err := testutil.MutualTLSState()
	require.NoError(t, err)
	return auth.WithTLSState(context.Background(), state)
}

func TestPeerAttestation_ChallengeThenSubmitStoresBoundEvidence(t *testing.T) {
	svc, store := newPeerAttestationService(t)
	ctx := mutualTLSContext(t)

	challenge, err := svc.PeerAttestationChallenge(ctx)
	require.NoError(t, err)
	assert.Len(t, challenge.Nonce, peergate.NonceLength)
	assert.True(t, challenge.ExpiresAt.After(time.Now()))

	req := &transport.SubmitPeerAttestationRequest{
		Quote:            []byte("quote"),
		Signature:        []byte("signature"),
		Nonce:            challenge.Nonce,
		PCRs:             map[int][]byte{7: make([]byte, 32)},
		AKCertificatePEM: []byte("ak"),
	}
	require.NoError(t, svc.SubmitPeerAttestation(ctx, req))

	require.Len(t, store.records, 1)
	for _, record := range store.records {
		assert.Equal(t, req.Quote, record.Evidence.Quote)
		assert.Equal(t, req.PCRs, record.Evidence.PCRs)
		assert.NotEmpty(t, record.ChannelBinding, "evidence is bound to the submitting connection")
		assert.False(t, record.Evidence.CollectedAt.IsZero(), "the collector stamps the receipt time")
	}

	err = svc.SubmitPeerAttestation(ctx, req)
	var challengeErr *peergate.ChallengeError
	assert.ErrorAs(t, err, &challengeErr, "a challenge answers once")
}

func TestPeerAttestation_RefusesACallerWithoutAClientCertificate(t *testing.T) {
	svc, store := newPeerAttestationService(t)
	var certErr *peergate.PeerCertificateError

	_, err := svc.PeerAttestationChallenge(context.Background())
	assert.ErrorAs(t, err, &certErr, "a unix-socket caller has no TLS state")

	err = svc.SubmitPeerAttestation(context.Background(), &transport.SubmitPeerAttestationRequest{Nonce: []byte("n")})
	assert.ErrorAs(t, err, &certErr)

	unverified := auth.WithTLSState(context.Background(), &tls.ConnectionState{HandshakeComplete: true})
	_, err = svc.PeerAttestationChallenge(unverified)
	assert.ErrorAs(t, err, &certErr, "a connection without a verified chain names no peer")
	assert.Empty(t, store.records)
}

func TestPeerAttestation_RefusesAWrongNonce(t *testing.T) {
	svc, store := newPeerAttestationService(t)
	ctx := mutualTLSContext(t)

	_, err := svc.PeerAttestationChallenge(ctx)
	require.NoError(t, err)
	err = svc.SubmitPeerAttestation(ctx, &transport.SubmitPeerAttestationRequest{Nonce: make([]byte, peergate.NonceLength)})
	var challengeErr *peergate.ChallengeError
	assert.ErrorAs(t, err, &challengeErr)
	assert.Empty(t, store.records)
}

func TestPeerAttestation_RequiresAGate(t *testing.T) {
	svc := &XKMSService{}
	ctx := mutualTLSContext(t)

	_, err := svc.PeerAttestationChallenge(ctx)
	assert.ErrorIs(t, err, ErrNotConfigured)
	assert.ErrorIs(t, svc.SubmitPeerAttestation(ctx, &transport.SubmitPeerAttestationRequest{}), ErrNotConfigured)

	wired, _ := newPeerAttestationService(t)
	assert.ErrorIs(t, wired.SubmitPeerAttestation(ctx, nil), ErrNilRequest)
}
