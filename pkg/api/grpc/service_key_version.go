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

	"github.com/jeremyhahn/go-xkms/pkg/api/grpc/pbconv"
	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// The key-version RPCs are the gRPC (and, over the same generated client,
// Unix) server side of the key-version API. Each authorizes the keys:*
// permission its (qrdb.v1.permission) option declares -- stated in the
// handler itself so the authorization scan reads it -- and delegates to
// XKMSService in the caller's tenant; RotateScopeKeys alone takes a tenant
// from the request, which the service binds to the caller.

// keyVersionCall runs call on the service, once the RPC has authorized its
// permission, and maps its error through the key-operation classification.
func keyVersionCall[R any](ctx context.Context, s *Service, call func(*xkms.XKMSService) (R, error)) (R, error) {
	var zero R
	if s.xkmsService == nil {
		return zero, status.Error(codes.Unavailable, xkms.ErrNotInitialized.Error())
	}
	resp, err := call(s.xkmsService)
	if err != nil {
		return zero, mapKeyOpError(ctx, s.xkmsService, err)
	}
	return resp, nil
}

// ListKeyVersions lists a key's versions.
func (s *Service) ListKeyVersions(ctx context.Context, req *pb.ListKeyVersionsRequest) (*pb.ListKeyVersionsResponse, error) {
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionList, req.GetKeyId()); err != nil {
		return nil, err
	}
	return keyVersionCall(ctx, s, func(x *xkms.XKMSService) (*pb.ListKeyVersionsResponse, error) {
		resp, err := x.ListKeyVersions(ctx, &transport.ListKeyVersionsRequest{
			Backend: req.GetBackend(), KeyID: req.GetKeyId(), TenantID: callerTenantID(ctx),
		})
		if err != nil {
			return nil, err
		}
		return pbconv.ListKeyVersionsResponseToProto(resp), nil
	})
}

// EnableKeyVersion enables a version of a key.
func (s *Service) EnableKeyVersion(ctx context.Context, req *pb.EnableKeyVersionRequest) (*pb.EnableKeyVersionResponse, error) {
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionRotate, req.GetKeyId()); err != nil {
		return nil, err
	}
	return keyVersionCall(ctx, s, func(x *xkms.XKMSService) (*pb.EnableKeyVersionResponse, error) {
		resp, err := x.EnableKeyVersion(ctx, keyVersionRequest(ctx, req.GetBackend(), req.GetKeyId(), req.GetVersion()))
		if err != nil {
			return nil, err
		}
		return pbconv.EnableKeyVersionResponseToProto(resp), nil
	})
}

// DisableKeyVersion disables a version of a key.
func (s *Service) DisableKeyVersion(ctx context.Context, req *pb.DisableKeyVersionRequest) (*pb.DisableKeyVersionResponse, error) {
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionRotate, req.GetKeyId()); err != nil {
		return nil, err
	}
	return keyVersionCall(ctx, s, func(x *xkms.XKMSService) (*pb.DisableKeyVersionResponse, error) {
		resp, err := x.DisableKeyVersion(ctx, keyVersionRequest(ctx, req.GetBackend(), req.GetKeyId(), req.GetVersion()))
		if err != nil {
			return nil, err
		}
		return pbconv.DisableKeyVersionResponseToProto(resp), nil
	})
}

// RetireKeyVersion retires a version of a key, deleting its key material.
func (s *Service) RetireKeyVersion(ctx context.Context, req *pb.RetireKeyVersionRequest) (*pb.RetireKeyVersionResponse, error) {
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionDelete, req.GetKeyId()); err != nil {
		return nil, err
	}
	return keyVersionCall(ctx, s, func(x *xkms.XKMSService) (*pb.RetireKeyVersionResponse, error) {
		resp, err := x.RetireKeyVersion(ctx, keyVersionRequest(ctx, req.GetBackend(), req.GetKeyId(), req.GetVersion()))
		if err != nil {
			return nil, err
		}
		return pbconv.RetireKeyVersionResponseToProto(resp), nil
	})
}

// EnableAllKeyVersions enables every disabled version of a key.
func (s *Service) EnableAllKeyVersions(ctx context.Context, req *pb.EnableAllKeyVersionsRequest) (*pb.EnableAllKeyVersionsResponse, error) {
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionRotate, req.GetKeyId()); err != nil {
		return nil, err
	}
	return keyVersionCall(ctx, s, func(x *xkms.XKMSService) (*pb.EnableAllKeyVersionsResponse, error) {
		resp, err := x.EnableAllKeyVersions(ctx, &transport.AllKeyVersionsRequest{
			Backend: req.GetBackend(), KeyID: req.GetKeyId(), TenantID: callerTenantID(ctx),
		})
		if err != nil {
			return nil, err
		}
		return pbconv.EnableAllKeyVersionsResponseToProto(resp), nil
	})
}

// DisableAllKeyVersions disables every non-current version of a key.
func (s *Service) DisableAllKeyVersions(ctx context.Context, req *pb.DisableAllKeyVersionsRequest) (*pb.DisableAllKeyVersionsResponse, error) {
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionRotate, req.GetKeyId()); err != nil {
		return nil, err
	}
	return keyVersionCall(ctx, s, func(x *xkms.XKMSService) (*pb.DisableAllKeyVersionsResponse, error) {
		resp, err := x.DisableAllKeyVersions(ctx, &transport.AllKeyVersionsRequest{
			Backend: req.GetBackend(), KeyID: req.GetKeyId(), TenantID: callerTenantID(ctx),
		})
		if err != nil {
			return nil, err
		}
		return pbconv.DisableAllKeyVersionsResponseToProto(resp), nil
	})
}

// RotateScopeKeys rotates every key of a tenant. The tenant is the
// request's, which the service binds to the caller: a tenant caller may name
// only its own.
func (s *Service) RotateScopeKeys(ctx context.Context, req *pb.RotateScopeKeysRequest) (*pb.RotateScopeKeysResponse, error) {
	if err := s.authorize(ctx, auth.ResourceKeys, auth.ActionRotate, req.GetTenantId()); err != nil {
		return nil, err
	}
	return keyVersionCall(ctx, s, func(x *xkms.XKMSService) (*pb.RotateScopeKeysResponse, error) {
		resp, err := x.RotateScopeKeys(ctx, &transport.RotateScopeKeysRequest{TenantID: req.GetTenantId()})
		if err != nil {
			return nil, err
		}
		return pbconv.RotateScopeKeysResponseToProto(resp), nil
	})
}

// keyVersionRequest builds the service request naming one version of a key
// in the caller's tenant.
func keyVersionRequest(ctx context.Context, backend, keyID string, version int32) *transport.KeyVersionRequest {
	return &transport.KeyVersionRequest{
		Backend:  backend,
		KeyID:    keyID,
		Version:  pbconv.KeyVersionFromProto(version),
		TenantID: callerTenantID(ctx),
	}
}
