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
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// The OIDCCredential* handlers are the gRPC (and, over the same generated
// client, Unix) server side of the OIDC credential API
// (pkg/oidc/credential). Each authorizes its oidc_credentials:* permission
// -- the one its (qrdb.v1.permission) option declares, stated in the handler
// itself so the authorization scan reads it -- and delegates to
// XKMSService, which derives the caller's principal and leaves the scope
// rules (tenant binding, owner-only personal credentials) to the credential
// service.

// oidcCredentialCall runs call on the service, once the RPC has authorized
// its permission, and maps its error through the OIDC credential
// classification.
func oidcCredentialCall[R any](s *Service, call func(*xkms.XKMSService) (R, error)) (R, error) {
	var zero R
	if s.xkmsService == nil {
		return zero, status.Error(codes.Unavailable, xkms.ErrNotInitialized.Error())
	}
	resp, err := call(s.xkmsService)
	if err != nil {
		return zero, mapOIDCCredentialError(err)
	}
	return resp, nil
}

// mapOIDCCredentialError converts an OIDC credential API error into a gRPC
// status error through apierrors.OIDCCredentialClassOf, which the MCP and
// REST handlers of the same API read too. Anything it does not classify is
// an internal fault.
func mapOIDCCredentialError(err error) error {
	if class, ok := apierrors.OIDCCredentialClassOf(err); ok {
		return status.Error(grpcCodeForClass(class), err.Error())
	}
	return status.Error(codes.Internal, err.Error())
}

// oidcCredentialView runs a credential operation that takes a reference and
// returns the credential's view.
func oidcCredentialView(ctx context.Context, s *Service, req *pb.OIDCCredentialRef,
	op func(*xkms.XKMSService, context.Context, *transport.OIDCCredentialRef) (*transport.OIDCCredential, error),
) (*pb.OIDCCredential, error) {
	return oidcCredentialCall(s, func(x *xkms.XKMSService) (*pb.OIDCCredential, error) {
		c, err := op(x, ctx, pbconv.OIDCCredentialRefFromProto(req))
		if err != nil {
			return nil, err
		}
		return pbconv.OIDCCredentialToProto(c), nil
	})
}

// OIDCCredentialCreate creates an OIDC credential.
func (s *Service) OIDCCredentialCreate(ctx context.Context, req *pb.OIDCCredentialCreateRequest) (*pb.OIDCCredential, error) {
	if err := s.authorize(ctx, auth.ResourceOIDCCredentials, auth.ActionCreate, req.GetRef().GetName()); err != nil {
		return nil, err
	}
	return oidcCredentialCall(s, func(x *xkms.XKMSService) (*pb.OIDCCredential, error) {
		c, err := x.OIDCCredentialCreate(ctx, pbconv.OIDCCredentialCreateRequestFromProto(req))
		if err != nil {
			return nil, err
		}
		return pbconv.OIDCCredentialToProto(c), nil
	})
}

// OIDCCredentialImport imports tokens into an OIDC credential.
func (s *Service) OIDCCredentialImport(ctx context.Context, req *pb.OIDCCredentialImportRequest) (*pb.OIDCCredential, error) {
	if err := s.authorize(ctx, auth.ResourceOIDCCredentials, auth.ActionUpdate, req.GetRef().GetName()); err != nil {
		return nil, err
	}
	return oidcCredentialCall(s, func(x *xkms.XKMSService) (*pb.OIDCCredential, error) {
		c, err := x.OIDCCredentialImport(ctx, pbconv.OIDCCredentialImportRequestFromProto(req))
		if err != nil {
			return nil, err
		}
		return pbconv.OIDCCredentialToProto(c), nil
	})
}

// OIDCCredentialGet returns an OIDC credential's public view.
func (s *Service) OIDCCredentialGet(ctx context.Context, req *pb.OIDCCredentialRef) (*pb.OIDCCredential, error) {
	if err := s.authorize(ctx, auth.ResourceOIDCCredentials, auth.ActionGet, req.GetName()); err != nil {
		return nil, err
	}
	return oidcCredentialView(ctx, s, req, (*xkms.XKMSService).OIDCCredentialGet)
}

// OIDCCredentialList lists the OIDC credentials the caller can see.
func (s *Service) OIDCCredentialList(ctx context.Context, req *pb.OIDCCredentialListRequest) (*pb.OIDCCredentialListResponse, error) {
	if err := s.authorize(ctx, auth.ResourceOIDCCredentials, auth.ActionList, ""); err != nil {
		return nil, err
	}
	return oidcCredentialCall(s, func(x *xkms.XKMSService) (*pb.OIDCCredentialListResponse, error) {
		resp, err := x.OIDCCredentialList(ctx, &transport.OIDCCredentialListRequest{TenantID: req.GetTenantId()})
		if err != nil {
			return nil, err
		}
		return pbconv.OIDCCredentialListResponseToProto(resp), nil
	})
}

// OIDCCredentialDelete deletes an OIDC credential.
func (s *Service) OIDCCredentialDelete(ctx context.Context, req *pb.OIDCCredentialRef) (*pb.OIDCCredentialDeleteResponse, error) {
	if err := s.authorize(ctx, auth.ResourceOIDCCredentials, auth.ActionDelete, req.GetName()); err != nil {
		return nil, err
	}
	return oidcCredentialCall(s, func(x *xkms.XKMSService) (*pb.OIDCCredentialDeleteResponse, error) {
		if err := x.OIDCCredentialDelete(ctx, pbconv.OIDCCredentialRefFromProto(req)); err != nil {
			return nil, err
		}
		return &pb.OIDCCredentialDeleteResponse{}, nil
	})
}

// OIDCCredentialRefresh refreshes an OIDC credential now.
func (s *Service) OIDCCredentialRefresh(ctx context.Context, req *pb.OIDCCredentialRef) (*pb.OIDCCredential, error) {
	if err := s.authorize(ctx, auth.ResourceOIDCCredentials, auth.ActionUpdate, req.GetName()); err != nil {
		return nil, err
	}
	return oidcCredentialView(ctx, s, req, (*xkms.XKMSService).OIDCCredentialRefresh)
}

// OIDCCredentialGetAccessToken returns a current access token of an OIDC
// credential.
func (s *Service) OIDCCredentialGetAccessToken(ctx context.Context, req *pb.OIDCCredentialRef) (*pb.OIDCAccessToken, error) {
	if err := s.authorize(ctx, auth.ResourceOIDCCredentials, auth.ActionToken, req.GetName()); err != nil {
		return nil, err
	}
	return oidcCredentialCall(s, func(x *xkms.XKMSService) (*pb.OIDCAccessToken, error) {
		tok, err := x.OIDCCredentialGetAccessToken(ctx, pbconv.OIDCCredentialRefFromProto(req))
		if err != nil {
			return nil, err
		}
		return pbconv.OIDCAccessTokenToProto(tok), nil
	})
}

// OIDCCredentialDeviceStart starts a device login for an OIDC credential.
func (s *Service) OIDCCredentialDeviceStart(ctx context.Context, req *pb.OIDCCredentialRef) (*pb.OIDCCredential, error) {
	if err := s.authorize(ctx, auth.ResourceOIDCCredentials, auth.ActionUpdate, req.GetName()); err != nil {
		return nil, err
	}
	return oidcCredentialView(ctx, s, req, (*xkms.XKMSService).OIDCCredentialDeviceStart)
}

// OIDCCredentialDevicePoll polls an OIDC credential's device login once.
func (s *Service) OIDCCredentialDevicePoll(ctx context.Context, req *pb.OIDCCredentialRef) (*pb.OIDCCredential, error) {
	if err := s.authorize(ctx, auth.ResourceOIDCCredentials, auth.ActionUpdate, req.GetName()); err != nil {
		return nil, err
	}
	return oidcCredentialView(ctx, s, req, (*xkms.XKMSService).OIDCCredentialDevicePoll)
}
