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
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// The AttestationAppraisal handlers are the gRPC (and, over the same
// generated client, Unix) server side of the attestation Verifier's
// endorsements, reference values and appraisal verb (go-xkms#1660). Each
// authorizes the permission its (qrdb.v1.permission) option declares, the
// pair the REST and MCP routes gate on, and delegates to XKMSService, which
// binds the call to the caller's tenant.

// attestationAppraisalCall runs call on the service, once the RPC has
// authorized its permission, and maps its error through the appraisal
// classification.
func attestationAppraisalCall[R any](s *Service, call func(*xkms.XKMSService) (R, error)) (R, error) {
	var zero R
	if s.xkmsService == nil {
		return zero, status.Error(codes.Unavailable, xkms.ErrNotInitialized.Error())
	}
	resp, err := call(s.xkmsService)
	if err != nil {
		return zero, mapAttestationAppraisalError(err)
	}
	return resp, nil
}

// mapAttestationAppraisalError converts an appraisal error into a gRPC
// status error. Anything the table does not classify is an internal fault.
func mapAttestationAppraisalError(err error) error {
	if class, ok := apierrors.AttestationAppraisalClassOf(err); ok {
		return status.Error(grpcCodeForClass(class), err.Error())
	}
	return status.Error(codes.Internal, err.Error())
}

// PutAttestationEndorsement stores a trust anchor.
func (s *Service) PutAttestationEndorsement(ctx context.Context, req *pb.PutAttestationEndorsementRequest) (*pb.AttestationEndorsement, error) {
	if err := s.authorize(ctx, auth.ResourceAttestationEndorsements, auth.ActionCreate, req.GetName()); err != nil {
		return nil, err
	}
	return attestationAppraisalCall(s, func(x *xkms.XKMSService) (*pb.AttestationEndorsement, error) {
		e, err := x.PutAttestationEndorsement(ctx, pbconv.PutAttestationEndorsementRequestFromProto(req))
		if err != nil {
			return nil, err
		}
		return pbconv.AttestationEndorsementToProto(e), nil
	})
}

// ListAttestationEndorsements lists the trust anchors, optionally by kind.
func (s *Service) ListAttestationEndorsements(ctx context.Context, req *pb.ListAttestationEndorsementsRequest) (*pb.ListAttestationEndorsementsResponse, error) {
	if err := s.authorize(ctx, auth.ResourceAttestationEndorsements, auth.ActionList, ""); err != nil {
		return nil, err
	}
	return attestationAppraisalCall(s, func(x *xkms.XKMSService) (*pb.ListAttestationEndorsementsResponse, error) {
		listReq := pbconv.ListAttestationEndorsementsRequestFromProto(req)
		if listReq == nil {
			listReq = &appraisal.ListEndorsementsRequest{}
		}
		resp, err := x.ListAttestationEndorsements(ctx, listReq)
		if err != nil {
			return nil, err
		}
		return pbconv.ListAttestationEndorsementsResponseToProto(resp), nil
	})
}

// DeleteAttestationEndorsement removes a trust anchor.
func (s *Service) DeleteAttestationEndorsement(ctx context.Context, req *pb.DeleteAttestationEndorsementRequest) (*pb.DeleteAttestationEndorsementResponse, error) {
	if err := s.authorize(ctx, auth.ResourceAttestationEndorsements, auth.ActionDelete, req.GetName()); err != nil {
		return nil, err
	}
	return attestationAppraisalCall(s, func(x *xkms.XKMSService) (*pb.DeleteAttestationEndorsementResponse, error) {
		if err := x.DeleteAttestationEndorsement(ctx, pbconv.DeleteAttestationEndorsementRequestFromProto(req)); err != nil {
			return nil, err
		}
		return &pb.DeleteAttestationEndorsementResponse{}, nil
	})
}

// PutAttestationReferenceValues verifies a signed CoRIM and stores its
// reference values.
func (s *Service) PutAttestationReferenceValues(ctx context.Context, req *pb.PutAttestationReferenceValuesRequest) (*pb.AttestationReferenceValues, error) {
	if err := s.authorize(ctx, auth.ResourceAttestationReferenceValues, auth.ActionCreate, req.GetName()); err != nil {
		return nil, err
	}
	return attestationAppraisalCall(s, func(x *xkms.XKMSService) (*pb.AttestationReferenceValues, error) {
		v, err := x.PutAttestationReferenceValues(ctx, pbconv.PutAttestationReferenceValuesRequestFromProto(req))
		if err != nil {
			return nil, err
		}
		return pbconv.AttestationReferenceValuesToProto(v), nil
	})
}

// GetAttestationReferenceValues returns stored reference values.
func (s *Service) GetAttestationReferenceValues(ctx context.Context, req *pb.GetAttestationReferenceValuesRequest) (*pb.AttestationReferenceValues, error) {
	if err := s.authorize(ctx, auth.ResourceAttestationReferenceValues, auth.ActionGet, req.GetName()); err != nil {
		return nil, err
	}
	return attestationAppraisalCall(s, func(x *xkms.XKMSService) (*pb.AttestationReferenceValues, error) {
		v, err := x.GetAttestationReferenceValues(ctx, pbconv.GetAttestationReferenceValuesRequestFromProto(req))
		if err != nil {
			return nil, err
		}
		return pbconv.AttestationReferenceValuesToProto(v), nil
	})
}

// ListAttestationReferenceValues lists the stored reference values.
func (s *Service) ListAttestationReferenceValues(ctx context.Context, _ *pb.ListAttestationReferenceValuesRequest) (*pb.ListAttestationReferenceValuesResponse, error) {
	if err := s.authorize(ctx, auth.ResourceAttestationReferenceValues, auth.ActionList, ""); err != nil {
		return nil, err
	}
	return attestationAppraisalCall(s, func(x *xkms.XKMSService) (*pb.ListAttestationReferenceValuesResponse, error) {
		resp, err := x.ListAttestationReferenceValues(ctx)
		if err != nil {
			return nil, err
		}
		return pbconv.ListAttestationReferenceValuesResponseToProto(resp), nil
	})
}

// DeleteAttestationReferenceValues removes stored reference values.
func (s *Service) DeleteAttestationReferenceValues(ctx context.Context, req *pb.DeleteAttestationReferenceValuesRequest) (*pb.DeleteAttestationReferenceValuesResponse, error) {
	if err := s.authorize(ctx, auth.ResourceAttestationReferenceValues, auth.ActionDelete, req.GetName()); err != nil {
		return nil, err
	}
	return attestationAppraisalCall(s, func(x *xkms.XKMSService) (*pb.DeleteAttestationReferenceValuesResponse, error) {
		if err := x.DeleteAttestationReferenceValues(ctx, pbconv.DeleteAttestationReferenceValuesRequestFromProto(req)); err != nil {
			return nil, err
		}
		return &pb.DeleteAttestationReferenceValuesResponse{}, nil
	})
}

// AppraiseAttestationQuote appraises a TPM quote and returns the
// attestation result.
func (s *Service) AppraiseAttestationQuote(ctx context.Context, req *pb.AppraiseAttestationQuoteRequest) (*pb.AttestationResult, error) {
	if err := s.authorize(ctx, auth.ResourceAttestationVerifier, auth.ActionVerify, req.GetReferenceValues()); err != nil {
		return nil, err
	}
	return attestationAppraisalCall(s, func(x *xkms.XKMSService) (*pb.AttestationResult, error) {
		result, err := x.AppraiseAttestationQuote(ctx, pbconv.AppraiseAttestationQuoteRequestFromProto(req))
		if err != nil {
			return nil, err
		}
		return pbconv.AttestationResultToProto(result), nil
	})
}

// AppraiseAndroidKeyAttestation appraises an Android Key Attestation chain
// against the stored Android attestation roots.
func (s *Service) AppraiseAndroidKeyAttestation(ctx context.Context, req *pb.AppraiseAndroidKeyAttestationRequest) (*pb.AttestationResult, error) {
	if err := s.authorize(ctx, auth.ResourceAttestationVerifier, auth.ActionVerify, ""); err != nil {
		return nil, err
	}
	return attestationAppraisalCall(s, func(x *xkms.XKMSService) (*pb.AttestationResult, error) {
		result, err := x.AppraiseAndroidKeyAttestation(ctx, pbconv.AppraiseAndroidKeyAttestationRequestFromProto(req))
		if err != nil {
			return nil, err
		}
		return pbconv.AttestationResultToProto(result), nil
	})
}

// AppraiseEKCertificate appraises a TPM endorsement-key certificate against
// the stored EK roots.
func (s *Service) AppraiseEKCertificate(ctx context.Context, req *pb.AppraiseEKCertificateRequest) (*pb.AttestationResult, error) {
	if err := s.authorize(ctx, auth.ResourceAttestationVerifier, auth.ActionVerify, ""); err != nil {
		return nil, err
	}
	return attestationAppraisalCall(s, func(x *xkms.XKMSService) (*pb.AttestationResult, error) {
		result, err := x.AppraiseEKCertificate(ctx, pbconv.AppraiseEKCertificateRequestFromProto(req))
		if err != nil {
			return nil, err
		}
		return pbconv.AttestationResultToProto(result), nil
	})
}
