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
	"math"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-xkms/pkg/api/apierrors"
	"github.com/jeremyhahn/go-xkms/pkg/api/grpc/pbconv"
	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// The TrustRoot* handlers are the gRPC (and, over the same generated client,
// Unix) server side of the platform trust-root store. They gate on the
// trust_roots resource.

// TrustRootList lists the trust roots, optionally of one purpose.
func (s *Service) TrustRootList(ctx context.Context, req *pb.TrustRootListRequest) (*pb.TrustRootListResponse, error) {
	if err := s.authorize(ctx, auth.ResourceTrustRoots, auth.ActionList, ""); err != nil {
		return nil, err
	}
	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}
	resp, err := s.xkmsService.TrustRootList(ctx, &transport.TrustRootListRequest{Purpose: req.GetPurpose()})
	if err != nil {
		return nil, mapTrustRootError(err)
	}
	return pbconv.TrustRootListResponseToProto(resp), nil
}

// TrustRootGet returns one trust root, its PEM included.
func (s *Service) TrustRootGet(ctx context.Context, req *pb.TrustRootRequest) (*pb.TrustRoot, error) {
	if err := s.authorize(ctx, auth.ResourceTrustRoots, auth.ActionGet, req.GetFingerprint()); err != nil {
		return nil, err
	}
	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}
	resp, err := s.xkmsService.TrustRootGet(ctx, &transport.TrustRootRequest{Fingerprint: req.GetFingerprint()})
	if err != nil {
		return nil, mapTrustRootError(err)
	}
	return pbconv.TrustRootToProto(resp), nil
}

// TrustRootImport adds the certificates of a PEM bundle.
func (s *Service) TrustRootImport(ctx context.Context, req *pb.TrustRootImportRequest) (*pb.TrustRootImportResponse, error) {
	if err := s.authorize(ctx, auth.ResourceTrustRoots, auth.ActionImport, ""); err != nil {
		return nil, err
	}
	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}
	resp, err := s.xkmsService.TrustRootImport(ctx, pbconv.TrustRootImportRequestFromProto(req))
	if err != nil {
		return nil, mapTrustRootError(err)
	}
	return &pb.TrustRootImportResponse{Added: clampInt32(resp.Added), Skipped: clampInt32(resp.Skipped)}, nil
}

// TrustRootQuarantine reclassifies a trust root as synced.
func (s *Service) TrustRootQuarantine(ctx context.Context, req *pb.TrustRootRequest) (*pb.TrustRoot, error) {
	if err := s.authorize(ctx, auth.ResourceTrustRoots, auth.ActionUpdate, req.GetFingerprint()); err != nil {
		return nil, err
	}
	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}
	resp, err := s.xkmsService.TrustRootQuarantine(ctx, &transport.TrustRootRequest{Fingerprint: req.GetFingerprint()})
	if err != nil {
		return nil, mapTrustRootError(err)
	}
	return pbconv.TrustRootToProto(resp), nil
}

// TrustRootRemove deletes a trust root.
func (s *Service) TrustRootRemove(ctx context.Context, req *pb.TrustRootRequest) (*pb.TrustRootRemoveResponse, error) {
	if err := s.authorize(ctx, auth.ResourceTrustRoots, auth.ActionDelete, req.GetFingerprint()); err != nil {
		return nil, err
	}
	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}
	if err := s.xkmsService.TrustRootRemove(ctx, &transport.TrustRootRequest{Fingerprint: req.GetFingerprint()}); err != nil {
		return nil, mapTrustRootError(err)
	}
	return &pb.TrustRootRemoveResponse{}, nil
}

// mapTrustRootError translates a trust-root store error into the gRPC
// status code a caller can act on, classifying it through
// apierrors.TrustRootSentinelClasses. Anything not in that table is an
// internal fault.
func mapTrustRootError(err error) error {
	if class, ok := apierrors.ClassOf(apierrors.TrustRootSentinelClasses, err); ok {
		return status.Error(grpcCodeForClass(class), err.Error())
	}
	return status.Error(codes.Internal, err.Error())
}

// clampInt32 narrows a count to the proto's int32, saturating at its maximum.
func clampInt32(n int) int32 {
	if n > math.MaxInt32 {
		return math.MaxInt32
	}
	return int32(n) // #nosec G115 -- bounded above
}
