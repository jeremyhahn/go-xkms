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

package grpc

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/peergate"
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

func (s *peerEvidenceRecorder) snapshot() map[string]peergate.Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]peergate.Record, len(s.records))
	for k, v := range s.records {
		out[k] = v
	}
	return out
}

// newPeerAttestationGRPC returns a service whose collector writes to the
// returned recorder.
func newPeerAttestationGRPC(t *testing.T) (*Service, *peerEvidenceRecorder) {
	t.Helper()
	store := &peerEvidenceRecorder{records: make(map[string]peergate.Record)}
	collector, err := peergate.NewCollector(peergate.CollectorConfig{Store: store})
	require.NoError(t, err)
	svc := &xkms.XKMSService{}
	svc.SetPeerEvidenceCollector(collector)
	return NewService(nil, nil, svc), store
}

// mutualTLSPeerCtx returns an authenticated context carrying the peer of an
// mTLS connection the way grpc-go hands it to a handler: as credentials.TLSInfo
// on the peer, with no TLS state of its own.
func mutualTLSPeerCtx(t *testing.T) context.Context {
	t.Helper()
	state, err := testutil.MutualTLSState()
	require.NoError(t, err)
	return peer.NewContext(platformScopeCtx("acme"), &peer.Peer{AuthInfo: credentials.TLSInfo{State: *state}})
}

// peerAttestationRPCs calls each peer attestation RPC on s.
func peerAttestationRPCs(s *Service) map[string]func(context.Context) error {
	return map[string]func(context.Context) error{
		"PeerAttestationChallenge": func(ctx context.Context) error {
			_, err := s.PeerAttestationChallenge(ctx, &pb.PeerAttestationChallengeRequest{})
			return err
		},
		"SubmitPeerAttestation": func(ctx context.Context) error {
			_, err := s.SubmitPeerAttestation(ctx, &pb.SubmitPeerAttestationRequest{Nonce: []byte("n")})
			return err
		},
	}
}

// TestPeerAttestationRPCs_ChallengeThenSubmit proves the RPCs reach the
// collector through the peer's TLS info: the challenge issues a nonce to the
// client certificate, the evidence answering it is stored with its PCRs, and
// a second answer is refused as a failed precondition.
func TestPeerAttestationRPCs_ChallengeThenSubmit(t *testing.T) {
	s, store := newPeerAttestationGRPC(t)
	ctx := mutualTLSPeerCtx(t)

	challenge, err := s.PeerAttestationChallenge(ctx, &pb.PeerAttestationChallengeRequest{})
	require.NoError(t, err)
	require.Len(t, challenge.GetNonce(), peergate.NonceLength)
	require.NotNil(t, challenge.GetExpiresAt())

	req := &pb.SubmitPeerAttestationRequest{
		Quote:            []byte("quote"),
		Signature:        []byte("signature"),
		Nonce:            challenge.GetNonce(),
		Pcrs:             map[uint32][]byte{7: make([]byte, 32)},
		AkCertificatePem: []byte("ak"),
	}
	_, err = s.SubmitPeerAttestation(ctx, req)
	require.NoError(t, err)

	records := store.snapshot()
	require.Len(t, records, 1)
	for _, record := range records {
		assert.Equal(t, req.GetQuote(), record.Evidence.Quote)
		assert.Equal(t, map[int][]byte{7: make([]byte, 32)}, record.Evidence.PCRs)
	}

	_, err = s.SubmitPeerAttestation(ctx, req)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err), "a challenge answers once")
}

// TestPeerAttestationRPCs_Unauthenticated proves a call without a verified
// client certificate -- no peer, or a peer without TLS as over a unix
// socket -- is refused as unauthenticated and stores nothing.
func TestPeerAttestationRPCs_Unauthenticated(t *testing.T) {
	s, store := newPeerAttestationGRPC(t)
	for name, ctx := range map[string]context.Context{
		"no peer":          platformScopeCtx("acme"),
		"peer without TLS": peer.NewContext(platformScopeCtx("acme"), &peer.Peer{}),
	} {
		t.Run(name, func(t *testing.T) {
			for rpc, call := range peerAttestationRPCs(s) {
				assert.Equal(t, codes.Unauthenticated, status.Code(call(ctx)), rpc)
			}
		})
	}
	assert.Empty(t, store.snapshot())
}

// TestPeerAttestationRPCs_Unavailable proves a server without the service or
// without the attested-caller gate answers both RPCs as unavailable.
func TestPeerAttestationRPCs_Unavailable(t *testing.T) {
	ctx := mutualTLSPeerCtx(t)
	for name, s := range map[string]*Service{
		"no service": NewService(nil, nil, nil),
		"no gate":    NewService(nil, nil, &xkms.XKMSService{}),
	} {
		t.Run(name, func(t *testing.T) {
			for rpc, call := range peerAttestationRPCs(s) {
				assert.Equal(t, codes.Unavailable, status.Code(call(ctx)), rpc)
			}
		})
	}
}

// TestPeerAttestationRPCs_PermissionDenied proves each RPC authorizes its
// peer_attestation:* permission before reaching the service.
func TestPeerAttestationRPCs_PermissionDenied(t *testing.T) {
	s := newDeniedService()
	for rpc, call := range peerAttestationRPCs(s) {
		t.Run(rpc, func(t *testing.T) {
			assert.Equal(t, codes.PermissionDenied, status.Code(call(deniedCtx())))
		})
	}
}

// TestPeerAttestationRPCs_NilSubmitRequest proves a nil request reaches the
// service as nil and is refused as an invalid argument.
func TestPeerAttestationRPCs_NilSubmitRequest(t *testing.T) {
	s, _ := newPeerAttestationGRPC(t)
	_, err := s.SubmitPeerAttestation(mutualTLSPeerCtx(t), nil)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// TestMapPeerAttestationError_Classifies proves classified errors keep their
// class's code and anything else is Internal.
func TestMapPeerAttestationError_Classifies(t *testing.T) {
	assert.Equal(t, codes.ResourceExhausted, status.Code(mapPeerAttestationError(&peergate.CapacityError{What: "challenges", Limit: 1})))
	assert.Equal(t, codes.Internal, status.Code(mapPeerAttestationError(errors.New("unclassified"))))
}
