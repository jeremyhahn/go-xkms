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
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-xkms/pkg/api/apierrors"
	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// The GetTransparencyLog* handlers are the gRPC (and, over the same generated
// client, Unix) server side of the CA transparency log's read verbs
// (docs/transparency-log). They gate on the vlog resource: vlog:head for the
// signed tree head, vlog:get for an entry and vlog:proof for a proof.

// GetTransparencyLogHead returns the log's current signed tree head.
func (s *Service) GetTransparencyLogHead(ctx context.Context, _ *pb.GetTransparencyLogHeadRequest) (*pb.GetTransparencyLogHeadResponse, error) {
	if err := s.authorize(ctx, auth.ResourceVlog, auth.ActionHead, ""); err != nil {
		return nil, err
	}
	if err := s.requireTransparencyLog(); err != nil {
		return nil, err
	}
	resp, err := s.xkmsService.GetTransparencyLogHead(ctx, &transport.GetTransparencyLogHeadRequest{})
	if err != nil {
		return nil, mapTransparencyLogError(err)
	}
	return &pb.GetTransparencyLogHeadResponse{
		Checkpoint: resp.Checkpoint,
		Origin:     resp.Origin,
		Size:       resp.Size,
		RootHash:   resp.RootHash,
	}, nil
}

// GetTransparencyLogEntry returns one encoded log entry.
func (s *Service) GetTransparencyLogEntry(ctx context.Context, req *pb.GetTransparencyLogEntryRequest) (*pb.GetTransparencyLogEntryResponse, error) {
	if err := s.authorize(ctx, auth.ResourceVlog, auth.ActionGet, ""); err != nil {
		return nil, err
	}
	if err := s.requireTransparencyLog(); err != nil {
		return nil, err
	}
	resp, err := s.xkmsService.GetTransparencyLogEntry(ctx, &transport.GetTransparencyLogEntryRequest{Index: req.GetIndex()})
	if err != nil {
		return nil, mapTransparencyLogError(err)
	}
	return &pb.GetTransparencyLogEntryResponse{Index: resp.Index, Entry: resp.Entry}, nil
}

// GetTransparencyLogInclusionProof returns an RFC 9162 §2.1.3 inclusion proof.
func (s *Service) GetTransparencyLogInclusionProof(ctx context.Context, req *pb.GetTransparencyLogInclusionProofRequest) (*pb.GetTransparencyLogInclusionProofResponse, error) {
	if err := s.authorize(ctx, auth.ResourceVlog, auth.ActionProof, ""); err != nil {
		return nil, err
	}
	if err := s.requireTransparencyLog(); err != nil {
		return nil, err
	}
	resp, err := s.xkmsService.GetTransparencyLogInclusionProof(ctx, &transport.GetTransparencyLogInclusionProofRequest{
		Index:    req.GetIndex(),
		TreeSize: req.GetTreeSize(),
	})
	if err != nil {
		return nil, mapTransparencyLogError(err)
	}
	return &pb.GetTransparencyLogInclusionProofResponse{Index: resp.Index, TreeSize: resp.TreeSize, Hashes: resp.Hashes}, nil
}

// GetTransparencyLogConsistencyProof returns an RFC 9162 §2.1.4 consistency
// proof.
func (s *Service) GetTransparencyLogConsistencyProof(ctx context.Context, req *pb.GetTransparencyLogConsistencyProofRequest) (*pb.GetTransparencyLogConsistencyProofResponse, error) {
	if err := s.authorize(ctx, auth.ResourceVlog, auth.ActionProof, ""); err != nil {
		return nil, err
	}
	if err := s.requireTransparencyLog(); err != nil {
		return nil, err
	}
	resp, err := s.xkmsService.GetTransparencyLogConsistencyProof(ctx, &transport.GetTransparencyLogConsistencyProofRequest{
		FirstSize:  req.GetFirstSize(),
		SecondSize: req.GetSecondSize(),
	})
	if err != nil {
		return nil, mapTransparencyLogError(err)
	}
	return &pb.GetTransparencyLogConsistencyProofResponse{FirstSize: resp.FirstSize, SecondSize: resp.SecondSize, Hashes: resp.Hashes}, nil
}

// AppendTransparencyLogExternal appends an external entry under the caller's
// SPIFFE ID. The service reads that ID from the call's verified TLS client
// certificate, so ctx carries the peer's TLS state.
func (s *Service) AppendTransparencyLogExternal(ctx context.Context, req *pb.AppendTransparencyLogExternalRequest) (*pb.AppendTransparencyLogExternalResponse, error) {
	if err := s.authorize(ctx, auth.ResourceVlog, auth.ActionAppend, ""); err != nil {
		return nil, err
	}
	if err := s.requireTransparencyLog(); err != nil {
		return nil, err
	}
	resp, err := s.xkmsService.AppendTransparencyLogExternal(peerTLSContext(ctx), &transport.AppendTransparencyLogExternalRequest{
		Payload: req.GetPayload(),
	})
	if err != nil {
		return nil, mapTransparencyLogError(err)
	}
	return &pb.AppendTransparencyLogExternalResponse{Index: resp.Index}, nil
}

// requireTransparencyLog reports Unavailable when the xkms service is not
// wired.
func (s *Service) requireTransparencyLog() error {
	if s.xkmsService == nil {
		return status.Error(codes.Unavailable, "xkms service not initialized")
	}
	return nil
}

// mapTransparencyLogError translates a transparency-log read error into the
// gRPC status code a caller can act on, classifying it through
// apierrors.TransparencyLogSentinelClasses. Anything not in that table is an
// internal fault.
func mapTransparencyLogError(err error) error {
	if class, ok := apierrors.ClassOf(apierrors.TransparencyLogSentinelClasses, err); ok {
		return status.Error(grpcCodeForClass(class), err.Error())
	}
	return status.Error(codes.Internal, err.Error())
}
