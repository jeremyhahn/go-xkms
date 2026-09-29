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

package mcp

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// The tpm.* and xkms.*TPMMode / xkms.tenantVTPM* handlers are the MCP server
// side of the TPM policy API (pkg/tpmpolicy). Each decodes its parameters
// into the transport request and delegates to XKMSService, which binds the
// target tenant and enforces system scope; they gate on the tpm_policy:*
// and tenants:* pairs in authz.go's methodPermissions.

// tpmPolicyCall decodes a P from req and runs call with it, mapping its
// error through the TPM policy classification.
func tpmPolicyCall[P, R any](s *Server, ctx context.Context, req *JSONRPCRequest, op string, call func(context.Context, *P) (R, error)) (interface{}, error) {
	if s.xkmsService == nil {
		return nil, mapTPMPolicyError(xkms.ErrNotConfigured, op)
	}
	var params P
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}
	resp, err := call(ctx, &params)
	if err != nil {
		return nil, mapTPMPolicyError(err, op)
	}
	return resp, nil
}

// tenantTPMCall decodes a tenant ID from req and runs call with it.
func tenantTPMCall[R any](s *Server, ctx context.Context, req *JSONRPCRequest, op string, call func(context.Context, string) (R, error)) (interface{}, error) {
	if s.xkmsService == nil {
		return nil, mapTPMPolicyError(xkms.ErrNotConfigured, op)
	}
	tenantID, err := tenantIDParam(req)
	if err != nil {
		return nil, err
	}
	resp, err := call(ctx, tenantID)
	if err != nil {
		return nil, mapTPMPolicyError(err, op)
	}
	return resp, nil
}

// handleTPMPolicyCreate handles tpm.policy.create.
func (s *Server) handleTPMPolicyCreate(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return tpmPolicyCall(s, ctx, req, "tpm policy create", s.xkmsService.TPMPolicyCreate)
}

// handleTPMPolicyGet handles tpm.policy.get.
func (s *Server) handleTPMPolicyGet(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return tpmPolicyCall(s, ctx, req, "tpm policy get", s.xkmsService.TPMPolicyGet)
}

// handleTPMPolicyList handles tpm.policy.list.
func (s *Server) handleTPMPolicyList(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return tpmPolicyCall(s, ctx, req, "tpm policy list", s.xkmsService.TPMPolicyList)
}

// handleTPMPolicyUpdate handles tpm.policy.update.
func (s *Server) handleTPMPolicyUpdate(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return tpmPolicyCall(s, ctx, req, "tpm policy update", s.xkmsService.TPMPolicyUpdate)
}

// handleTPMPolicyRevoke handles tpm.policy.revoke.
func (s *Server) handleTPMPolicyRevoke(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return tpmPolicyCall(s, ctx, req, "tpm policy revoke", s.xkmsService.TPMPolicyRevoke)
}

// handleTPMPolicyVerify handles tpm.policy.verify.
func (s *Server) handleTPMPolicyVerify(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return tpmPolicyCall(s, ctx, req, "tpm policy verify", s.xkmsService.TPMPolicyVerify)
}

// handleTPMPolicyDelete handles tpm.policy.delete, answering with the
// deleted policy's name.
func (s *Server) handleTPMPolicyDelete(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return tpmPolicyCall(s, ctx, req, "tpm policy delete", func(ctx context.Context, params *transport.TPMPolicyDeleteRequest) (map[string]string, error) {
		if err := s.xkmsService.TPMPolicyDelete(ctx, params); err != nil {
			return nil, err
		}
		return map[string]string{"name": params.Name}, nil
	})
}

// handleTPMPolicyObjects handles tpm.policy.objects.
func (s *Server) handleTPMPolicyObjects(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return tpmPolicyCall(s, ctx, req, "tpm policy objects", s.xkmsService.TPMPolicyObjects)
}

// handleTPMPolicyAutoUnseal handles tpm.policy.autoUnseal.
func (s *Server) handleTPMPolicyAutoUnseal(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return tpmPolicyCall(s, ctx, req, "tpm policy auto-unseal", s.xkmsService.TPMPolicySetAutoUnseal)
}

// handleTPMObjectPolicy handles tpm.object.policy.
func (s *Server) handleTPMObjectPolicy(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return tpmPolicyCall(s, ctx, req, "tpm object policy", s.xkmsService.TPMObjectPolicy)
}

// handleTPMAuthorityRotate handles tpm.authority.rotate.
func (s *Server) handleTPMAuthorityRotate(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return tpmPolicyCall(s, ctx, req, "tpm authority rotate", s.xkmsService.TPMPolicyRotateAuthority)
}

// handleGetTenantTPMMode handles xkms.getTenantTPMMode.
func (s *Server) handleGetTenantTPMMode(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return tenantTPMCall(s, ctx, req, "get tenant tpm mode", s.xkmsService.GetTenantTPMMode)
}

// handleSetTenantTPMMode handles xkms.setTenantTPMMode.
func (s *Server) handleSetTenantTPMMode(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return tpmPolicyCall(s, ctx, req, "set tenant tpm mode", s.xkmsService.SetTenantTPMMode)
}

// handleTenantVTPMStatus handles xkms.tenantVTPMStatus.
func (s *Server) handleTenantVTPMStatus(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return tenantTPMCall(s, ctx, req, "tenant vtpm status", s.xkmsService.TenantVTPMStatus)
}

// handleTenantVTPMStart handles xkms.tenantVTPMStart.
func (s *Server) handleTenantVTPMStart(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return tenantTPMCall(s, ctx, req, "tenant vtpm start", s.xkmsService.TenantVTPMStart)
}

// handleTenantVTPMStop handles xkms.tenantVTPMStop.
func (s *Server) handleTenantVTPMStop(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return tenantTPMCall(s, ctx, req, "tenant vtpm stop", s.xkmsService.TenantVTPMStop)
}
