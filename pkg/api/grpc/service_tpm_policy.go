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

// The TPMPolicy* and tenant TPM handlers are the gRPC (and, over the same
// generated client, Unix) server side of the TPM policy API
// (pkg/tpmpolicy). Each authorizes its tpm_policy:* or tenants:* permission
// -- the same pair its (qrdb.v1.permission) option declares, stated in the
// handler itself so the authorization scan reads it -- and delegates to
// XKMSService, which binds the target tenant and enforces system scope.

// tpmPolicyCall runs call on the service, once the RPC has authorized its
// permission, and maps its error through the TPM policy classification.
func tpmPolicyCall[R any](s *Service, call func(*xkms.XKMSService) (R, error)) (R, error) {
	var zero R
	if s.xkmsService == nil {
		return zero, status.Error(codes.Unavailable, xkms.ErrNotInitialized.Error())
	}
	resp, err := call(s.xkmsService)
	if err != nil {
		return zero, mapTPMPolicyError(err)
	}
	return resp, nil
}

// mapTPMPolicyError converts a TPM policy API error into a gRPC status error
// through apierrors.TPMPolicyClassOf, which the MCP and REST handlers of the
// same API read too. Anything it does not classify is an internal fault.
func mapTPMPolicyError(err error) error {
	if class, ok := apierrors.TPMPolicyClassOf(err); ok {
		return status.Error(grpcCodeForClass(class), err.Error())
	}
	return status.Error(codes.Internal, err.Error())
}

// TPMPolicyCreate creates a named TPM policy.
func (s *Service) TPMPolicyCreate(ctx context.Context, req *pb.TPMPolicyCreateRequest) (*pb.TPMPolicy, error) {
	if err := s.authorize(ctx, auth.ResourceTPMPolicy, auth.ActionCreate, req.GetName()); err != nil {
		return nil, err
	}
	return tpmPolicyCall(s, func(x *xkms.XKMSService) (*pb.TPMPolicy, error) {
		p, err := x.TPMPolicyCreate(ctx, pbconv.TPMPolicyCreateRequestFromProto(req))
		if err != nil {
			return nil, err
		}
		return pbconv.TPMPolicyToProto(p), nil
	})
}

// TPMPolicyGet returns a named TPM policy.
func (s *Service) TPMPolicyGet(ctx context.Context, req *pb.TPMPolicyRequest) (*pb.TPMPolicy, error) {
	if err := s.authorize(ctx, auth.ResourceTPMPolicy, auth.ActionGet, req.GetName()); err != nil {
		return nil, err
	}
	return tpmPolicyCall(s, func(x *xkms.XKMSService) (*pb.TPMPolicy, error) {
		p, err := x.TPMPolicyGet(ctx, pbconv.TPMPolicyRequestFromProto(req))
		if err != nil {
			return nil, err
		}
		return pbconv.TPMPolicyToProto(p), nil
	})
}

// TPMPolicyList returns a tenant's TPM policies.
func (s *Service) TPMPolicyList(ctx context.Context, req *pb.TPMPolicyListRequest) (*pb.TPMPolicyListResponse, error) {
	if err := s.authorize(ctx, auth.ResourceTPMPolicy, auth.ActionList, ""); err != nil {
		return nil, err
	}
	return tpmPolicyCall(s, func(x *xkms.XKMSService) (*pb.TPMPolicyListResponse, error) {
		resp, err := x.TPMPolicyList(ctx, &transport.TPMPolicyListRequest{TenantID: req.GetTenantId()})
		if err != nil {
			return nil, err
		}
		return pbconv.TPMPolicyListResponseToProto(resp), nil
	})
}

// TPMPolicyUpdate re-captures and re-approves a TPM policy.
func (s *Service) TPMPolicyUpdate(ctx context.Context, req *pb.TPMPolicyRequest) (*pb.TPMPolicy, error) {
	if err := s.authorize(ctx, auth.ResourceTPMPolicy, auth.ActionUpdate, req.GetName()); err != nil {
		return nil, err
	}
	return tpmPolicyCall(s, func(x *xkms.XKMSService) (*pb.TPMPolicy, error) {
		p, err := x.TPMPolicyUpdate(ctx, pbconv.TPMPolicyRequestFromProto(req))
		if err != nil {
			return nil, err
		}
		return pbconv.TPMPolicyToProto(p), nil
	})
}

// TPMPolicyRevoke withdraws a TPM policy's approval.
func (s *Service) TPMPolicyRevoke(ctx context.Context, req *pb.TPMPolicyRequest) (*pb.TPMPolicy, error) {
	if err := s.authorize(ctx, auth.ResourceTPMPolicy, auth.ActionRevoke, req.GetName()); err != nil {
		return nil, err
	}
	return tpmPolicyCall(s, func(x *xkms.XKMSService) (*pb.TPMPolicy, error) {
		p, err := x.TPMPolicyRevoke(ctx, pbconv.TPMPolicyRequestFromProto(req))
		if err != nil {
			return nil, err
		}
		return pbconv.TPMPolicyToProto(p), nil
	})
}

// TPMPolicyVerify compares a TPM policy's PCR values with the live ones.
func (s *Service) TPMPolicyVerify(ctx context.Context, req *pb.TPMPolicyRequest) (*pb.TPMPolicyVerifyResponse, error) {
	if err := s.authorize(ctx, auth.ResourceTPMPolicy, auth.ActionVerify, req.GetName()); err != nil {
		return nil, err
	}
	return tpmPolicyCall(s, func(x *xkms.XKMSService) (*pb.TPMPolicyVerifyResponse, error) {
		v, err := x.TPMPolicyVerify(ctx, pbconv.TPMPolicyRequestFromProto(req))
		if err != nil {
			return nil, err
		}
		return pbconv.TPMPolicyVerifyResponseToProto(v), nil
	})
}

// TPMPolicyDelete deletes a TPM policy no object is assigned to.
func (s *Service) TPMPolicyDelete(ctx context.Context, req *pb.TPMPolicyDeleteRequest) (*pb.TPMPolicyDeleteResponse, error) {
	if err := s.authorize(ctx, auth.ResourceTPMPolicy, auth.ActionDelete, req.GetName()); err != nil {
		return nil, err
	}
	return tpmPolicyCall(s, func(x *xkms.XKMSService) (*pb.TPMPolicyDeleteResponse, error) {
		if err := x.TPMPolicyDelete(ctx, pbconv.TPMPolicyDeleteRequestFromProto(req)); err != nil {
			return nil, err
		}
		return &pb.TPMPolicyDeleteResponse{}, nil
	})
}

// TPMPolicyObjects lists the objects assigned to a TPM policy.
func (s *Service) TPMPolicyObjects(ctx context.Context, req *pb.TPMPolicyRequest) (*pb.TPMPolicyObjectsResponse, error) {
	if err := s.authorize(ctx, auth.ResourceTPMPolicy, auth.ActionGet, req.GetName()); err != nil {
		return nil, err
	}
	return tpmPolicyCall(s, func(x *xkms.XKMSService) (*pb.TPMPolicyObjectsResponse, error) {
		resp, err := x.TPMPolicyObjects(ctx, pbconv.TPMPolicyRequestFromProto(req))
		if err != nil {
			return nil, err
		}
		return pbconv.TPMPolicyObjectsResponseToProto(resp), nil
	})
}

// TPMPolicySetAutoUnseal sets or clears a TPM policy's auto-unseal mark.
func (s *Service) TPMPolicySetAutoUnseal(ctx context.Context, req *pb.TPMPolicyAutoUnsealRequest) (*pb.TPMPolicy, error) {
	if err := s.authorize(ctx, auth.ResourceTPMPolicy, auth.ActionUpdate, req.GetName()); err != nil {
		return nil, err
	}
	return tpmPolicyCall(s, func(x *xkms.XKMSService) (*pb.TPMPolicy, error) {
		p, err := x.TPMPolicySetAutoUnseal(ctx, pbconv.TPMPolicyAutoUnsealRequestFromProto(req))
		if err != nil {
			return nil, err
		}
		return pbconv.TPMPolicyToProto(p), nil
	})
}

// TPMPolicySetDescription replaces a TPM policy's description.
func (s *Service) TPMPolicySetDescription(ctx context.Context, req *pb.TPMPolicyDescriptionRequest) (*pb.TPMPolicy, error) {
	if err := s.authorize(ctx, auth.ResourceTPMPolicy, auth.ActionUpdate, req.GetName()); err != nil {
		return nil, err
	}
	return tpmPolicyCall(s, func(x *xkms.XKMSService) (*pb.TPMPolicy, error) {
		p, err := x.TPMPolicySetDescription(ctx, pbconv.TPMPolicyDescriptionRequestFromProto(req))
		if err != nil {
			return nil, err
		}
		return pbconv.TPMPolicyToProto(p), nil
	})
}

// TPMObjectPolicy returns the TPM policy a key or sealed object was created
// under.
func (s *Service) TPMObjectPolicy(ctx context.Context, req *pb.TPMObjectPolicyRequest) (*pb.TPMObjectPolicyResponse, error) {
	if err := s.authorize(ctx, auth.ResourceTPMPolicy, auth.ActionGet, req.GetKeyId()); err != nil {
		return nil, err
	}
	return tpmPolicyCall(s, func(x *xkms.XKMSService) (*pb.TPMObjectPolicyResponse, error) {
		resp, err := x.TPMObjectPolicy(ctx, pbconv.TPMObjectPolicyRequestFromProto(req))
		if err != nil {
			return nil, err
		}
		return pbconv.TPMObjectPolicyResponseToProto(resp), nil
	})
}

// TPMPolicyRotateAuthority rotates a tenant's TPM policy authority.
func (s *Service) TPMPolicyRotateAuthority(ctx context.Context, req *pb.TPMAuthorityRotateRequest) (*pb.TPMAuthorityRotateResponse, error) {
	if err := s.authorize(ctx, auth.ResourceTPMPolicy, auth.ActionRotate, req.GetTenantId()); err != nil {
		return nil, err
	}
	return tpmPolicyCall(s, func(x *xkms.XKMSService) (*pb.TPMAuthorityRotateResponse, error) {
		resp, err := x.TPMPolicyRotateAuthority(ctx, &transport.TPMAuthorityRotateRequest{TenantID: req.GetTenantId()})
		if err != nil {
			return nil, err
		}
		return pbconv.TPMAuthorityRotateResponseToProto(resp), nil
	})
}

// GetTenantTPMMode returns a tenant's TPM mode.
func (s *Service) GetTenantTPMMode(ctx context.Context, req *pb.TenantTPMModeRequest) (*pb.TenantTPMModeResponse, error) {
	if err := s.authorize(ctx, auth.ResourceTenants, auth.ActionRead, req.GetTenantId()); err != nil {
		return nil, err
	}
	return tpmPolicyCall(s, func(x *xkms.XKMSService) (*pb.TenantTPMModeResponse, error) {
		resp, err := x.GetTenantTPMMode(ctx, req.GetTenantId())
		if err != nil {
			return nil, err
		}
		return pbconv.TenantTPMModeResponseToProto(resp), nil
	})
}

// SetTenantTPMMode changes a tenant's TPM mode.
func (s *Service) SetTenantTPMMode(ctx context.Context, req *pb.SetTenantTPMModeRequest) (*pb.TenantTPMModeResponse, error) {
	if err := s.authorize(ctx, auth.ResourceTenants, auth.ActionSetTPMMode, req.GetTenantId()); err != nil {
		return nil, err
	}
	return tpmPolicyCall(s, func(x *xkms.XKMSService) (*pb.TenantTPMModeResponse, error) {
		resp, err := x.SetTenantTPMMode(ctx, pbconv.SetTenantTPMModeRequestFromProto(req))
		if err != nil {
			return nil, err
		}
		return pbconv.TenantTPMModeResponseToProto(resp), nil
	})
}

// TenantVTPMStatus reports a tenant's virtual TPM.
func (s *Service) TenantVTPMStatus(ctx context.Context, req *pb.TenantVTPMRequest) (*pb.TenantVTPMStatusResponse, error) {
	if err := s.authorize(ctx, auth.ResourceTenants, auth.ActionRead, req.GetTenantId()); err != nil {
		return nil, err
	}
	return tpmPolicyCall(s, func(x *xkms.XKMSService) (*pb.TenantVTPMStatusResponse, error) {
		resp, err := x.TenantVTPMStatus(ctx, req.GetTenantId())
		if err != nil {
			return nil, err
		}
		return pbconv.TenantVTPMStatusResponseToProto(resp), nil
	})
}

// TenantVTPMStart starts a tenant's virtual TPM.
func (s *Service) TenantVTPMStart(ctx context.Context, req *pb.TenantVTPMRequest) (*pb.TenantVTPMStatusResponse, error) {
	if err := s.authorize(ctx, auth.ResourceTenants, auth.ActionSetTPMMode, req.GetTenantId()); err != nil {
		return nil, err
	}
	return tpmPolicyCall(s, func(x *xkms.XKMSService) (*pb.TenantVTPMStatusResponse, error) {
		resp, err := x.TenantVTPMStart(ctx, req.GetTenantId())
		if err != nil {
			return nil, err
		}
		return pbconv.TenantVTPMStatusResponseToProto(resp), nil
	})
}

// TenantVTPMStop stops a tenant's virtual TPM.
func (s *Service) TenantVTPMStop(ctx context.Context, req *pb.TenantVTPMRequest) (*pb.TenantVTPMStatusResponse, error) {
	if err := s.authorize(ctx, auth.ResourceTenants, auth.ActionSetTPMMode, req.GetTenantId()); err != nil {
		return nil, err
	}
	return tpmPolicyCall(s, func(x *xkms.XKMSService) (*pb.TenantVTPMStatusResponse, error) {
		resp, err := x.TenantVTPMStop(ctx, req.GetTenantId())
		if err != nil {
			return nil, err
		}
		return pbconv.TenantVTPMStatusResponseToProto(resp), nil
	})
}
