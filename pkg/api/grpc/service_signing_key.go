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
	"github.com/jeremyhahn/go-xkms/pkg/api/grpc/pbconv"
	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// The SigningKey handlers are the gRPC (and, over the same generated client,
// Unix) server side of the repository signing-key API (go-xkms#1697). Each
// authorizes the attestation_signing_keys:* permission its
// (qrdb.v1.permission) option declares, stated in the handler itself so the
// authorization scan reads it, and delegates to XKMSService, which binds the
// call to the caller's tenant.

// signingKeyCall runs call on the service, once the RPC has authorized its
// permission, and maps its error through the signing-key classification.
func signingKeyCall[R any](s *Service, call func(*xkms.XKMSService) (R, error)) (R, error) {
	var zero R
	if s.xkmsService == nil {
		return zero, status.Error(codes.Unavailable, xkms.ErrNotInitialized.Error())
	}
	resp, err := call(s.xkmsService)
	if err != nil {
		return zero, mapSigningKeyError(err)
	}
	return resp, nil
}

// mapSigningKeyError converts a signing-key API error into a gRPC status
// error through apierrors.SigningKeyClassOf, which the MCP and REST handlers
// read too. Anything it does not classify is an internal fault.
func mapSigningKeyError(err error) error {
	if class, ok := apierrors.SigningKeyClassOf(err); ok {
		return status.Error(grpcCodeForClass(class), err.Error())
	}
	return status.Error(codes.Internal, err.Error())
}

// SetSigningKeyBinding names the key that signs a repository.
func (s *Service) SetSigningKeyBinding(ctx context.Context, req *pb.SetSigningKeyBindingRequest) (*pb.SigningKeyBinding, error) {
	if err := s.authorize(ctx, auth.ResourceAttestationSigningKeys, auth.ActionBind, req.GetRepository()); err != nil {
		return nil, err
	}
	return signingKeyCall(s, func(x *xkms.XKMSService) (*pb.SigningKeyBinding, error) {
		binding, err := x.SetSigningKeyBinding(ctx, pbconv.SetSigningKeyBindingRequestFromProto(req))
		if err != nil {
			return nil, err
		}
		return pbconv.SigningKeyBindingToProto(binding), nil
	})
}

// GetSigningKeyBinding returns a repository's binding.
func (s *Service) GetSigningKeyBinding(ctx context.Context, req *pb.GetSigningKeyBindingRequest) (*pb.SigningKeyBinding, error) {
	if err := s.authorize(ctx, auth.ResourceAttestationSigningKeys, auth.ActionGet, req.GetRepository()); err != nil {
		return nil, err
	}
	return signingKeyCall(s, func(x *xkms.XKMSService) (*pb.SigningKeyBinding, error) {
		binding, err := x.GetSigningKeyBinding(ctx, pbconv.GetSigningKeyBindingRequestFromProto(req))
		if err != nil {
			return nil, err
		}
		return pbconv.SigningKeyBindingToProto(binding), nil
	})
}

// ListSigningKeyBindings returns the caller's tenant's bindings.
func (s *Service) ListSigningKeyBindings(ctx context.Context, _ *pb.ListSigningKeyBindingsRequest) (*pb.ListSigningKeyBindingsResponse, error) {
	if err := s.authorize(ctx, auth.ResourceAttestationSigningKeys, auth.ActionList, ""); err != nil {
		return nil, err
	}
	return signingKeyCall(s, func(x *xkms.XKMSService) (*pb.ListSigningKeyBindingsResponse, error) {
		resp, err := x.ListSigningKeyBindings(ctx)
		if err != nil {
			return nil, err
		}
		return pbconv.ListSigningKeyBindingsResponseToProto(resp), nil
	})
}

// DeleteSigningKeyBinding removes a repository's binding.
func (s *Service) DeleteSigningKeyBinding(ctx context.Context, req *pb.DeleteSigningKeyBindingRequest) (*pb.DeleteSigningKeyBindingResponse, error) {
	if err := s.authorize(ctx, auth.ResourceAttestationSigningKeys, auth.ActionBind, req.GetRepository()); err != nil {
		return nil, err
	}
	return signingKeyCall(s, func(x *xkms.XKMSService) (*pb.DeleteSigningKeyBindingResponse, error) {
		if err := x.DeleteSigningKeyBinding(ctx, pbconv.DeleteSigningKeyBindingRequestFromProto(req)); err != nil {
			return nil, err
		}
		return &pb.DeleteSigningKeyBindingResponse{}, nil
	})
}

// ResolveSigningKey returns the key that signs a repository.
func (s *Service) ResolveSigningKey(ctx context.Context, req *pb.ResolveSigningKeyRequest) (*pb.SigningKeyResolution, error) {
	if err := s.authorize(ctx, auth.ResourceAttestationSigningKeys, auth.ActionGet, req.GetRepository()); err != nil {
		return nil, err
	}
	return signingKeyCall(s, func(x *xkms.XKMSService) (*pb.SigningKeyResolution, error) {
		resolution, err := x.ResolveSigningKey(ctx, pbconv.ResolveSigningKeyRequestFromProto(req))
		if err != nil {
			return nil, err
		}
		return pbconv.SigningKeyResolutionToProto(resolution), nil
	})
}

// SignCoRIM signs a repository's CoRIM with the key ResolveSigningKey
// returns.
func (s *Service) SignCoRIM(ctx context.Context, req *pb.SignCoRIMRequest) (*pb.SignedCoRIM, error) {
	if err := s.authorize(ctx, auth.ResourceAttestationSigningKeys, auth.ActionSign, req.GetRepository()); err != nil {
		return nil, err
	}
	return signingKeyCall(s, func(x *xkms.XKMSService) (*pb.SignedCoRIM, error) {
		signed, err := x.SignCoRIM(ctx, pbconv.SignCoRIMRequestFromProto(req))
		if err != nil {
			return nil, err
		}
		return pbconv.SignedCoRIMToProto(signed), nil
	})
}
