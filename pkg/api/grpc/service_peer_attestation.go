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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-xkms/pkg/api/apierrors"
	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// The peer attestation handlers are the gRPC server side of the
// attested-caller verbs (pkg/attestation/peergate). Each authorizes its
// peer_attestation:* permission -- the one its (qrdb.v1.permission) option
// declares -- and delegates to XKMSService, which identifies the caller by
// the verified client certificate of the call's TLS connection.

// PeerAttestationChallenge issues a single-use nonce to the caller's
// certificate.
func (s *Service) PeerAttestationChallenge(ctx context.Context, _ *pb.PeerAttestationChallengeRequest) (*pb.PeerAttestationChallengeResponse, error) {
	if err := s.authorize(ctx, auth.ResourcePeerAttestation, auth.ActionChallenge, ""); err != nil {
		return nil, err
	}
	return peerAttestationCall(s, func(x *xkms.XKMSService) (*pb.PeerAttestationChallengeResponse, error) {
		challenge, err := x.PeerAttestationChallenge(peerTLSContext(ctx))
		if err != nil {
			return nil, err
		}
		return &pb.PeerAttestationChallengeResponse{
			Nonce:     challenge.Nonce,
			ExpiresAt: timestamppb.New(challenge.ExpiresAt),
		}, nil
	})
}

// SubmitPeerAttestation answers the caller's outstanding challenge with a
// TPM quote.
func (s *Service) SubmitPeerAttestation(ctx context.Context, req *pb.SubmitPeerAttestationRequest) (*pb.SubmitPeerAttestationResponse, error) {
	if err := s.authorize(ctx, auth.ResourcePeerAttestation, auth.ActionSubmit, ""); err != nil {
		return nil, err
	}
	return peerAttestationCall(s, func(x *xkms.XKMSService) (*pb.SubmitPeerAttestationResponse, error) {
		if err := x.SubmitPeerAttestation(peerTLSContext(ctx), submitPeerAttestationFromProto(req)); err != nil {
			return nil, err
		}
		return &pb.SubmitPeerAttestationResponse{}, nil
	})
}

// peerAttestationCall runs call on the service, once the RPC has authorized
// its permission, and maps its error through the peer attestation
// classification.
func peerAttestationCall[R any](s *Service, call func(*xkms.XKMSService) (R, error)) (R, error) {
	var zero R
	if s.xkmsService == nil {
		return zero, status.Error(codes.Unavailable, xkms.ErrNotInitialized.Error())
	}
	resp, err := call(s.xkmsService)
	if err != nil {
		return zero, mapPeerAttestationError(err)
	}
	return resp, nil
}

// mapPeerAttestationError maps a peer attestation error to a gRPC status
// through apierrors.PeerAttestationClassOf, Internal when unclassified.
func mapPeerAttestationError(err error) error {
	if class, ok := apierrors.PeerAttestationClassOf(err); ok {
		return status.Error(grpcCodeForClass(class), err.Error())
	}
	return status.Error(codes.Internal, err.Error())
}

// peerTLSContext returns ctx carrying the call's TLS state, the carrier the
// service reads the caller's certificate from. A context that already
// carries one keeps it; a call over a connection without TLS (a unix
// socket) gets none, and the service refuses it.
func peerTLSContext(ctx context.Context) context.Context {
	if auth.TLSStateFromContext(ctx) != nil {
		return ctx
	}
	p, ok := peer.FromContext(ctx)
	if !ok {
		return ctx
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return ctx
	}
	return auth.WithTLSState(ctx, &tlsInfo.State)
}

// submitPeerAttestationFromProto converts the wire request to the service
// request; a nil request converts to nil, which the service refuses.
func submitPeerAttestationFromProto(req *pb.SubmitPeerAttestationRequest) *transport.SubmitPeerAttestationRequest {
	if req == nil {
		return nil
	}
	var pcrs map[int][]byte
	if len(req.GetPcrs()) > 0 {
		pcrs = make(map[int][]byte, len(req.GetPcrs()))
		for index, value := range req.GetPcrs() {
			pcrs[int(index)] = value
		}
	}
	return &transport.SubmitPeerAttestationRequest{
		Quote:            req.GetQuote(),
		Signature:        req.GetSignature(),
		Nonce:            req.GetNonce(),
		PCRs:             pcrs,
		AKCertificatePEM: req.GetAkCertificatePem(),
	}
}
