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
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/seal/policy"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// The Policy* handlers are the gRPC (and, over the same generated client,
// Unix) server side of TPM 2.0 PCR-bank sealed-secret authorization policies
// (pkg/seal/policy). go-xkms#691 minted the policy:* permission family
// (pkg/auth.ResourcePolicy): go-qrdb's canonical registry does not declare
// it upstream, so pkg/apimodule/module_scopes.go declares its tenancy
// scope, the way it already does for keys:read/write, ssh:use, and
// bootstrap:read.

// PolicyCreate creates a new PCR policy, capturing the current PCR values
// for the specified bank and indices.
func (s *Service) PolicyCreate(ctx context.Context, req *pb.PolicyCreateRequest) (*pb.PolicyCreateResponse, error) {
	if req == nil || req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if err := s.authorize(ctx, auth.ResourcePolicy, auth.ActionCreate, req.Name); err != nil {
		return nil, err
	}
	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}
	resp, err := s.xkmsService.PolicyCreate(ctx, &transport.PolicyCreateRequest{
		Name: req.Name,
		Bank: req.Bank,
		PCRs: pcrsFromProto(req.Pcrs),
	})
	if err != nil {
		return nil, mapPolicyError(err)
	}
	return &pb.PolicyCreateResponse{
		Name:      resp.Name,
		Bank:      resp.Bank,
		Pcrs:      pcrsToProto(resp.PCRs),
		Values:    pcrValuesToProto(resp.Values),
		CreatedAt: resp.CreatedAt,
	}, nil
}

// PolicyGet retrieves a PCR policy by name.
func (s *Service) PolicyGet(ctx context.Context, req *pb.PolicyGetRequest) (*pb.PolicyGetResponse, error) {
	if req == nil || req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if err := s.authorize(ctx, auth.ResourcePolicy, auth.ActionGet, req.Name); err != nil {
		return nil, err
	}
	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}
	resp, err := s.xkmsService.PolicyGet(ctx, &transport.PolicyGetRequest{Name: req.Name})
	if err != nil {
		return nil, mapPolicyError(err)
	}
	return policyGetResponseToProto(resp), nil
}

// PolicyList returns all registered PCR policies.
func (s *Service) PolicyList(ctx context.Context, _ *pb.PolicyListRequest) (*pb.PolicyListResponse, error) {
	if err := s.authorize(ctx, auth.ResourcePolicy, auth.ActionList, ""); err != nil {
		return nil, err
	}
	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}
	resp, err := s.xkmsService.PolicyList(ctx)
	if err != nil {
		return nil, mapPolicyError(err)
	}
	policies := make([]*pb.PolicyGetResponse, 0, len(resp.Policies))
	for i := range resp.Policies {
		policies = append(policies, policyGetResponseToProto(&resp.Policies[i]))
	}
	return &pb.PolicyListResponse{
		Policies: policies,
		Total:    int32(resp.Total), // #nosec G115 - policy count fits in int32
	}, nil
}

// PolicyDelete deletes a PCR policy by name.
func (s *Service) PolicyDelete(ctx context.Context, req *pb.PolicyDeleteRequest) (*pb.PolicyDeleteResponse, error) {
	if req == nil || req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if err := s.authorize(ctx, auth.ResourcePolicy, auth.ActionDelete, req.Name); err != nil {
		return nil, err
	}
	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}
	if err := s.xkmsService.PolicyDelete(ctx, &transport.PolicyDeleteRequest{Name: req.Name}); err != nil {
		return nil, mapPolicyError(err)
	}
	return &pb.PolicyDeleteResponse{}, nil
}

// PolicyRefresh re-captures a PCR policy from the platform's current PCR
// values.
func (s *Service) PolicyRefresh(ctx context.Context, req *pb.PolicyRefreshRequest) (*pb.PolicyGetResponse, error) {
	if req == nil || req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if err := s.authorize(ctx, auth.ResourcePolicy, auth.ActionRefresh, req.Name); err != nil {
		return nil, err
	}
	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}
	resp, err := s.xkmsService.PolicyRefresh(ctx, &transport.PolicyRefreshRequest{Name: req.Name})
	if err != nil {
		return nil, mapPolicyError(err)
	}
	return policyGetResponseToProto(resp), nil
}

// PolicyVerify verifies a PCR policy against the platform's current PCR
// values.
func (s *Service) PolicyVerify(ctx context.Context, req *pb.PolicyVerifyRequest) (*pb.PolicyVerifyResponse, error) {
	if req == nil || req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if err := s.authorize(ctx, auth.ResourcePolicy, auth.ActionVerify, req.Name); err != nil {
		return nil, err
	}
	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}
	resp, err := s.xkmsService.PolicyVerify(ctx, &transport.PolicyVerifyRequest{Name: req.Name})
	if err != nil {
		return nil, mapPolicyError(err)
	}
	return &pb.PolicyVerifyResponse{
		Name:    resp.Name,
		Valid:   resp.Valid,
		Message: resp.Message,
	}, nil
}

// PolicyExport serializes a named policy to a JSON document.
func (s *Service) PolicyExport(ctx context.Context, req *pb.PolicyExportRequest) (*pb.PolicyExportResponse, error) {
	if req == nil || req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if err := s.authorize(ctx, auth.ResourcePolicy, auth.ActionExport, req.Name); err != nil {
		return nil, err
	}
	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}
	resp, err := s.xkmsService.PolicyExport(ctx, &transport.PolicyExportRequest{Name: req.Name})
	if err != nil {
		return nil, mapPolicyError(err)
	}
	return &pb.PolicyExportResponse{Data: resp.Data}, nil
}

// policyGetResponseToProto converts a transport.PolicyGetResponse to its
// proto wire representation.
func policyGetResponseToProto(resp *transport.PolicyGetResponse) *pb.PolicyGetResponse {
	return &pb.PolicyGetResponse{
		Name:      resp.Name,
		Bank:      resp.Bank,
		Pcrs:      pcrsToProto(resp.PCRs),
		Values:    pcrValuesToProto(resp.Values),
		CreatedAt: resp.CreatedAt,
		UpdatedAt: resp.UpdatedAt,
	}
}

// pcrsToProto converts a PCR index slice to its proto (int32) representation.
func pcrsToProto(pcrs []int) []int32 {
	out := make([]int32, len(pcrs))
	for i, v := range pcrs {
		out[i] = int32(v) // #nosec G115 - PCR indices are 0-23
	}
	return out
}

// pcrValuesToProto converts a PCR index-to-hex-value map to its proto
// (int32 key) representation.
func pcrValuesToProto(values map[int]string) map[int32]string {
	out := make(map[int32]string, len(values))
	for idx, v := range values {
		idx32 := int32(idx) // #nosec G115 - PCR indices are 0-23
		out[idx32] = v
	}
	return out
}

// pcrsFromProto converts a proto (int32) PCR index slice to the servicer's
// native []int representation.
func pcrsFromProto(pcrs []int32) []int {
	out := make([]int, len(pcrs))
	for i, v := range pcrs {
		out[i] = int(v)
	}
	return out
}

// mapPolicyError translates a PCR policy error into the gRPC status code a
// caller can act on, so a capability refusal or validation error never
// surfaces as an opaque Internal error.
func mapPolicyError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, xkms.ErrNotConfigured):
		return status.Error(codes.Unavailable, "policy manager not configured")
	case errors.Is(err, xkms.ErrNilRequest):
		return status.Error(codes.InvalidArgument, "request is required")
	case errors.Is(err, policy.ErrPolicyNotFound):
		return status.Error(codes.NotFound, "policy not found")
	case errors.Is(err, policy.ErrPolicyExists):
		return status.Error(codes.AlreadyExists, "policy with this name already exists")
	case errors.Is(err, policy.ErrInvalidName):
		return status.Error(codes.InvalidArgument, "policy name must not be empty")
	case errors.Is(err, policy.ErrInvalidBank):
		return status.Error(codes.InvalidArgument, "PCR bank must not be empty")
	case errors.Is(err, policy.ErrUnsupportedBank):
		return status.Error(codes.InvalidArgument, "unsupported PCR bank algorithm")
	case errors.Is(err, policy.ErrNoPCRsSelected):
		return status.Error(codes.InvalidArgument, "at least one PCR index is required")
	case errors.Is(err, policy.ErrPCRIndexOutOfRange):
		return status.Error(codes.InvalidArgument, "PCR index out of range (must be 0-23)")
	case errors.Is(err, policy.ErrDuplicatePCRIndex):
		return status.Error(codes.InvalidArgument, "duplicate PCR index")
	case errors.Is(err, policy.ErrExportFailed):
		return status.Error(codes.Internal, "failed to export policy")
	default:
		return status.Error(codes.Internal, err.Error())
	}
}
