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

package mcp

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// The policy.* handlers are the MCP server side of TPM 2.0 PCR-bank
// sealed-secret authorization policies (pkg/seal/policy). They gate on the
// policy:* permission family (pkg/api/mcp/authz.go's methodPermissions),
// matching the gRPC PolicyCreate/Get/... RPCs' (qrdb.v1.permission) options.

// ErrPolicyNotConfigured is returned when no policy manager is wired into
// the server.
var ErrPolicyNotConfigured = xkms.ErrNotConfigured

// handlePolicyCreate handles the policy.create method.
func (s *Server) handlePolicyCreate(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	if s.xkmsService == nil {
		return nil, mapPolicyError(ErrPolicyNotConfigured, "policy create")
	}
	var params transport.PolicyCreateRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}
	resp, err := s.xkmsService.PolicyCreate(ctx, &params)
	if err != nil {
		return nil, mapPolicyError(err, "policy create")
	}
	return resp, nil
}

// handlePolicyGet handles the policy.get method.
func (s *Server) handlePolicyGet(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	if s.xkmsService == nil {
		return nil, mapPolicyError(ErrPolicyNotConfigured, "policy get")
	}
	var params transport.PolicyGetRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}
	resp, err := s.xkmsService.PolicyGet(ctx, &params)
	if err != nil {
		return nil, mapPolicyError(err, "policy get")
	}
	return resp, nil
}

// handlePolicyList handles the policy.list method.
func (s *Server) handlePolicyList(ctx context.Context, _ *JSONRPCRequest) (interface{}, error) {
	if s.xkmsService == nil {
		return nil, mapPolicyError(ErrPolicyNotConfigured, "policy list")
	}
	resp, err := s.xkmsService.PolicyList(ctx)
	if err != nil {
		return nil, mapPolicyError(err, "policy list")
	}
	return resp, nil
}

// handlePolicyDelete handles the policy.delete method.
func (s *Server) handlePolicyDelete(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	if s.xkmsService == nil {
		return nil, mapPolicyError(ErrPolicyNotConfigured, "policy delete")
	}
	var params transport.PolicyDeleteRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}
	if err := s.xkmsService.PolicyDelete(ctx, &params); err != nil {
		return nil, mapPolicyError(err, "policy delete")
	}
	return map[string]string{"name": params.Name}, nil
}

// handlePolicyRefresh handles the policy.refresh method.
func (s *Server) handlePolicyRefresh(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	if s.xkmsService == nil {
		return nil, mapPolicyError(ErrPolicyNotConfigured, "policy refresh")
	}
	var params transport.PolicyRefreshRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}
	resp, err := s.xkmsService.PolicyRefresh(ctx, &params)
	if err != nil {
		return nil, mapPolicyError(err, "policy refresh")
	}
	return resp, nil
}

// handlePolicyVerify handles the policy.verify method.
func (s *Server) handlePolicyVerify(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	if s.xkmsService == nil {
		return nil, mapPolicyError(ErrPolicyNotConfigured, "policy verify")
	}
	var params transport.PolicyVerifyRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}
	resp, err := s.xkmsService.PolicyVerify(ctx, &params)
	if err != nil {
		return nil, mapPolicyError(err, "policy verify")
	}
	return resp, nil
}

// handlePolicyExport handles the policy.export method.
func (s *Server) handlePolicyExport(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	if s.xkmsService == nil {
		return nil, mapPolicyError(ErrPolicyNotConfigured, "policy export")
	}
	var params transport.PolicyExportRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}
	resp, err := s.xkmsService.PolicyExport(ctx, &params)
	if err != nil {
		return nil, mapPolicyError(err, "policy export")
	}
	return resp, nil
}
