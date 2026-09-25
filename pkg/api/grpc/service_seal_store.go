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

// The SealStore* handlers are the gRPC (and, over the same generated client,
// Unix) server side of the machine-local sealed credential store. They gate
// on the keys resource, matching the PKCS#11 remote-state handlers, since
// both persist key-protection material sealed to the host's hardware.

// SealStorePut stores a secret in the platform-sealed store.
func (s *Service) SealStorePut(ctx context.Context, req *pb.SealStorePutRequest) (*pb.SealStorePutResponse, error) {
	if req == nil || req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionWrite, req.Name); err != nil {
		return nil, err
	}
	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}
	if err := s.xkmsService.SealStorePut(ctx, &transport.SealStorePutRequest{
		Name:   req.Name,
		Secret: req.Secret,
	}); err != nil {
		return nil, mapSealStoreError(err)
	}
	return &pb.SealStorePutResponse{Name: req.Name}, nil
}

// SealStoreGet retrieves a secret from the platform-sealed store.
func (s *Service) SealStoreGet(ctx context.Context, req *pb.SealStoreGetRequest) (*pb.SealStoreGetResponse, error) {
	if req == nil || req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionRead, req.Name); err != nil {
		return nil, err
	}
	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}
	resp, err := s.xkmsService.SealStoreGet(ctx, &transport.SealStoreGetRequest{Name: req.Name})
	if err != nil {
		return nil, mapSealStoreError(err)
	}
	return &pb.SealStoreGetResponse{Name: resp.Name, Secret: resp.Secret}, nil
}

// SealStoreDelete deletes a secret from the platform-sealed store.
func (s *Service) SealStoreDelete(ctx context.Context, req *pb.SealStoreDeleteRequest) (*pb.SealStoreDeleteResponse, error) {
	if req == nil || req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionDelete, req.Name); err != nil {
		return nil, err
	}
	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}
	if err := s.xkmsService.SealStoreDelete(ctx, &transport.SealStoreDeleteRequest{Name: req.Name}); err != nil {
		return nil, mapSealStoreError(err)
	}
	return &pb.SealStoreDeleteResponse{}, nil
}

// SealStoreList lists all stored secret names in the platform-sealed store.
func (s *Service) SealStoreList(ctx context.Context, _ *pb.SealStoreListRequest) (*pb.SealStoreListResponse, error) {
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionList, ""); err != nil {
		return nil, err
	}
	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}
	resp, err := s.xkmsService.SealStoreList(ctx)
	if err != nil {
		return nil, mapSealStoreError(err)
	}
	return &pb.SealStoreListResponse{Names: resp.Names}, nil
}

// SealStoreReseal reseals a secret with the current platform sealing key.
func (s *Service) SealStoreReseal(ctx context.Context, req *pb.SealStoreResealRequest) (*pb.SealStoreResealResponse, error) {
	if req == nil || req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionWrite, req.Name); err != nil {
		return nil, err
	}
	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}
	if err := s.xkmsService.SealStoreReseal(ctx, &transport.SealStoreResealRequest{Name: req.Name}); err != nil {
		return nil, mapSealStoreError(err)
	}
	return &pb.SealStoreResealResponse{Name: req.Name}, nil
}

// SealStoreStatus returns the platform-sealed store status.
func (s *Service) SealStoreStatus(ctx context.Context, _ *pb.SealStoreStatusRequest) (*pb.SealStoreStatusResponse, error) {
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionRead, ""); err != nil {
		return nil, err
	}
	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}
	resp, err := s.xkmsService.SealStoreStatus(ctx)
	if err != nil {
		return nil, mapSealStoreError(err)
	}
	return &pb.SealStoreStatusResponse{
		Available:   resp.Available,
		SealerId:    resp.SealerID,
		SecretCount: int32(resp.SecretCount), // #nosec G115 - secret count fits in int32
		SecretNames: resp.SecretNames,
	}, nil
}

// mapSealStoreError translates a platform-sealed store error into the gRPC
// status code a caller can act on, classifying it through
// apierrors.SealStoreSentinelClasses -- the table go-xkms#921 made this
// package share with pkg/api/mcp's mirror of this function -- so a
// capability refusal never surfaces as an opaque Internal error. Anything
// not in that table is an internal fault.
func mapSealStoreError(err error) error {
	if err == nil {
		return nil
	}
	if class, ok := apierrors.ClassOf(apierrors.SealStoreSentinelClasses, err); ok {
		return status.Error(grpcCodeForClass(class), err.Error())
	}
	return status.Error(codes.Internal, err.Error())
}
