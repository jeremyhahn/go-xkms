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

// The verdict handlers are the gRPC (and, over the same generated client,
// Unix) server side of the continuous attestation verdict verbs
// (go-xkms#2088). Each authorizes the attestation_verdicts:* permission its
// (qrdb.v1.permission) option declares, stated in the handler itself so the
// authorization scan reads it, and delegates to XKMSService, which binds the
// call to the caller's tenant.

// verdictCall runs call on the service, once the RPC has authorized its
// permission, and maps its error through the verdict classification.
func verdictCall[R any](s *Service, call func(*xkms.XKMSService) (R, error)) (R, error) {
	var zero R
	if s.xkmsService == nil {
		return zero, status.Error(codes.Unavailable, xkms.ErrNotInitialized.Error())
	}
	resp, err := call(s.xkmsService)
	if err != nil {
		return zero, mapVerdictError(err)
	}
	return resp, nil
}

// mapVerdictError converts a verdict error into a gRPC status error through
// apierrors.VerdictClassOf, which the MCP and REST handlers read too.
// Anything it does not classify is an internal fault.
func mapVerdictError(err error) error {
	if class, ok := apierrors.VerdictClassOf(err); ok {
		return status.Error(grpcCodeForClass(class), err.Error())
	}
	return status.Error(codes.Internal, err.Error())
}

// ListAttestationVerdicts returns a device's verdicts, oldest first.
func (s *Service) ListAttestationVerdicts(ctx context.Context, req *pb.AttestationVerdictRequest) (*pb.ListAttestationVerdictsResponse, error) {
	if err := s.authorize(ctx, auth.ResourceAttestationVerdicts, auth.ActionList, req.GetDeviceId()); err != nil {
		return nil, err
	}
	return verdictCall(s, func(x *xkms.XKMSService) (*pb.ListAttestationVerdictsResponse, error) {
		list, err := x.ListAttestationVerdicts(ctx, pbconv.AttestationVerdictRequestFromProto(req))
		if err != nil {
			return nil, err
		}
		return pbconv.ListAttestationVerdictsResponseToProto(list), nil
	})
}

// GetLatestAttestationVerdict returns a device's newest verdict.
func (s *Service) GetLatestAttestationVerdict(ctx context.Context, req *pb.AttestationVerdictRequest) (*pb.AttestationVerdict, error) {
	if err := s.authorize(ctx, auth.ResourceAttestationVerdicts, auth.ActionGet, req.GetDeviceId()); err != nil {
		return nil, err
	}
	return verdictCall(s, func(x *xkms.XKMSService) (*pb.AttestationVerdict, error) {
		verdict, err := x.GetLatestAttestationVerdict(ctx, pbconv.AttestationVerdictRequestFromProto(req))
		if err != nil {
			return nil, err
		}
		return pbconv.AttestationVerdictToProto(verdict), nil
	})
}

// ReattestDevice re-attests a device now and returns the verdict.
func (s *Service) ReattestDevice(ctx context.Context, req *pb.AttestationVerdictRequest) (*pb.AttestationVerdict, error) {
	if err := s.authorize(ctx, auth.ResourceAttestationVerdicts, auth.ActionCreate, req.GetDeviceId()); err != nil {
		return nil, err
	}
	return verdictCall(s, func(x *xkms.XKMSService) (*pb.AttestationVerdict, error) {
		verdict, err := x.ReattestDevice(ctx, pbconv.AttestationVerdictRequestFromProto(req))
		if err != nil {
			return nil, err
		}
		return pbconv.AttestationVerdictToProto(verdict), nil
	})
}
