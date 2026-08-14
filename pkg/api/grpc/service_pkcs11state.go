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

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// The PKCS11State* handlers are the gRPC (and, over the same generated client,
// Unix) server side of the remote-mode PKCS#11 module's persistence. They gate
// on the keys resource — the records are a token's key/object state — resolve
// the concrete XKMSService, and translate the opaque record verbatim.

// pkcs11StateServiceReady reports the service-unavailable error if the XKMSService
// is not wired, so the five handlers share one nil check.
func (s *Service) pkcs11StateServiceReady() error {
	if s.xkmsService == nil {
		return status.Error(codes.Unavailable, "xkms service not initialized")
	}
	return nil
}

func (s *Service) PKCS11StatePut(ctx context.Context, req *pb.PKCS11StatePutRequest) (*pb.PKCS11StatePutResponse, error) {
	if req == nil || req.Token == "" {
		return nil, status.Error(codes.InvalidArgument, "token is required")
	}
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionWrite, req.Token); err != nil {
		return nil, err
	}
	if err := s.pkcs11StateServiceReady(); err != nil {
		return nil, err
	}
	if _, err := s.xkmsService.PKCS11StatePut(ctx, &transport.PKCS11StatePutRequest{
		TenantID: req.TenantId, Token: req.Token, Key: req.Key, Value: req.Value,
	}); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &pb.PKCS11StatePutResponse{}, nil
}

func (s *Service) PKCS11StatePutIfAbsent(ctx context.Context, req *pb.PKCS11StatePutIfAbsentRequest) (*pb.PKCS11StatePutIfAbsentResponse, error) {
	if req == nil || req.Token == "" {
		return nil, status.Error(codes.InvalidArgument, "token is required")
	}
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionWrite, req.Token); err != nil {
		return nil, err
	}
	if err := s.pkcs11StateServiceReady(); err != nil {
		return nil, err
	}
	resp, err := s.xkmsService.PKCS11StatePutIfAbsent(ctx, &transport.PKCS11StatePutIfAbsentRequest{
		TenantID: req.TenantId, Token: req.Token, Key: req.Key, Value: req.Value,
	})
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &pb.PKCS11StatePutIfAbsentResponse{Stored: resp.Stored}, nil
}

func (s *Service) PKCS11StateCAS(ctx context.Context, req *pb.PKCS11StateCASRequest) (*pb.PKCS11StateCASResponse, error) {
	if req == nil || req.Token == "" {
		return nil, status.Error(codes.InvalidArgument, "token is required")
	}
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionWrite, req.Token); err != nil {
		return nil, err
	}
	if err := s.pkcs11StateServiceReady(); err != nil {
		return nil, err
	}
	resp, err := s.xkmsService.PKCS11StateCAS(ctx, &transport.PKCS11StateCASRequest{
		TenantID: req.TenantId, Token: req.Token, Key: req.Key,
		Expected: req.Expected, New: req.New, ExpectAbsent: req.ExpectAbsent,
	})
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &pb.PKCS11StateCASResponse{Swapped: resp.Swapped, Current: resp.Current}, nil
}

func (s *Service) PKCS11StateGet(ctx context.Context, req *pb.PKCS11StateGetRequest) (*pb.PKCS11StateGetResponse, error) {
	if req == nil || req.Token == "" {
		return nil, status.Error(codes.InvalidArgument, "token is required")
	}
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionRead, req.Token); err != nil {
		return nil, err
	}
	if err := s.pkcs11StateServiceReady(); err != nil {
		return nil, err
	}
	resp, err := s.xkmsService.PKCS11StateGet(ctx, &transport.PKCS11StateGetRequest{
		TenantID: req.TenantId, Token: req.Token, Key: req.Key,
	})
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &pb.PKCS11StateGetResponse{Value: resp.Value, Found: resp.Found}, nil
}

func (s *Service) PKCS11StateDelete(ctx context.Context, req *pb.PKCS11StateDeleteRequest) (*pb.PKCS11StateDeleteResponse, error) {
	if req == nil || req.Token == "" {
		return nil, status.Error(codes.InvalidArgument, "token is required")
	}
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionWrite, req.Token); err != nil {
		return nil, err
	}
	if err := s.pkcs11StateServiceReady(); err != nil {
		return nil, err
	}
	if _, err := s.xkmsService.PKCS11StateDelete(ctx, &transport.PKCS11StateDeleteRequest{
		TenantID: req.TenantId, Token: req.Token, Key: req.Key,
	}); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &pb.PKCS11StateDeleteResponse{}, nil
}

func (s *Service) PKCS11StateList(ctx context.Context, req *pb.PKCS11StateListRequest) (*pb.PKCS11StateListResponse, error) {
	if req == nil || req.Token == "" {
		return nil, status.Error(codes.InvalidArgument, "token is required")
	}
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionRead, req.Token); err != nil {
		return nil, err
	}
	if err := s.pkcs11StateServiceReady(); err != nil {
		return nil, err
	}
	resp, err := s.xkmsService.PKCS11StateList(ctx, &transport.PKCS11StateListRequest{
		TenantID: req.TenantId, Token: req.Token, Prefix: req.Prefix,
	})
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &pb.PKCS11StateListResponse{Keys: resp.Keys}, nil
}
