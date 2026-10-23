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

// The key management handlers decode the params, scope the request to the
// caller's tenant and hand it to the service; keyVersionCall and tenantCall
// map the service's errors through the key-operation classification.

// The per-request tenant and key ID accessors keyVersionCall needs.
func setKeyManagementTenant(p *transport.KeyManagementRequest, tenant string) { p.TenantID = tenant }
func keyManagementKeyID(p *transport.KeyManagementRequest) string             { return p.KeyID }
func setPublicKeyTenant(p *transport.GetPublicKeyRequest, tenant string)      { p.TenantID = tenant }
func publicKeyKeyID(p *transport.GetPublicKeyRequest) string                  { return p.KeyID }
func setRevokeKeyTenant(p *transport.RevokeKeyRequest, tenant string)         { p.TenantID = tenant }
func revokeKeyKeyID(p *transport.RevokeKeyRequest) string                     { return p.KeyID }
func setKeyStatusTenant(p *transport.UpdateKeyStatusRequest, tenant string)   { p.TenantID = tenant }
func keyStatusKeyID(p *transport.UpdateKeyStatusRequest) string               { return p.KeyID }
func setMetadataTenant(p *transport.UpdateKeyMetadataRequest, tenant string)  { p.TenantID = tenant }
func metadataKeyID(p *transport.UpdateKeyMetadataRequest) string              { return p.KeyID }
func setKeyPolicyTenant(p *transport.SetKeyPolicyRequest, tenant string)      { p.TenantID = tenant }
func keyPolicyKeyID(p *transport.SetKeyPolicyRequest) string                  { return p.KeyID }
func setRotationTenant(p *transport.SetKeyRotationPolicyRequest, tenant string) {
	p.TenantID = tenant
}
func rotationKeyID(p *transport.SetKeyRotationPolicyRequest) string       { return p.KeyID }
func setSafetyTenant(p *transport.SetKeySafetyRequest, tenant string)     { p.TenantID = tenant }
func safetyKeyID(p *transport.SetKeySafetyRequest) string                 { return p.KeyID }
func setBackendTenant(p *transport.BackendRequest, tenant string)         { p.TenantID = tenant }
func setSafetyCheckTenant(p *transport.SafetyCheckRequest, tenant string) { p.TenantID = tenant }
func setSafetyReportTenant(p *transport.SafetyReportRequest, tenant string) {
	p.TenantID = tenant
}

// tenantCall decodes the optional params of a request that names no key,
// scopes it to the caller's tenant and runs call with it, mapping its error
// through the key-operation classification.
func tenantCall[P, R any](s *Server, ctx context.Context, req *JSONRPCRequest, setTenant func(*P, string), call func(context.Context, *P) (R, error)) (interface{}, error) {
	if s.xkmsService == nil {
		return nil, mapKeyOpError(xkms.ErrNotInitialized)
	}
	var params P
	if len(req.Params) > 0 {
		if err := decodeParams(req, &params); err != nil {
			return nil, err
		}
	}
	setTenant(&params, callerTenantID(ctx))
	resp, err := call(ctx, &params)
	if err != nil {
		return nil, mapKeyOpError(err)
	}
	return resp, nil
}

// handleGetPublicKey handles xkms.getPublicKey.
func (s *Server) handleGetPublicKey(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return keyVersionCall(s, ctx, req, setPublicKeyTenant, publicKeyKeyID, s.xkmsService.GetPublicKey)
}

// handleRevokeKey handles xkms.revokeKey.
func (s *Server) handleRevokeKey(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return keyVersionCall(s, ctx, req, setRevokeKeyTenant, revokeKeyKeyID, s.xkmsService.RevokeKey)
}

// handleUpdateKeyStatus handles xkms.updateKeyStatus.
func (s *Server) handleUpdateKeyStatus(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return keyVersionCall(s, ctx, req, setKeyStatusTenant, keyStatusKeyID, s.xkmsService.UpdateKeyStatus)
}

// handleGetKeyMetadata handles xkms.getKeyMetadata.
func (s *Server) handleGetKeyMetadata(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return keyVersionCall(s, ctx, req, setKeyManagementTenant, keyManagementKeyID, s.xkmsService.GetKeyMetadata)
}

// handleUpdateKeyMetadata handles xkms.updateKeyMetadata.
func (s *Server) handleUpdateKeyMetadata(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return keyVersionCall(s, ctx, req, setMetadataTenant, metadataKeyID, s.xkmsService.UpdateKeyMetadata)
}

// handleSetKeyPolicy handles xkms.setKeyPolicy.
func (s *Server) handleSetKeyPolicy(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return keyVersionCall(s, ctx, req, setKeyPolicyTenant, keyPolicyKeyID, s.xkmsService.SetKeyPolicy)
}

// handleGetKeyPolicy handles xkms.getKeyPolicy.
func (s *Server) handleGetKeyPolicy(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return keyVersionCall(s, ctx, req, setKeyManagementTenant, keyManagementKeyID, s.xkmsService.GetKeyPolicy)
}

// handleDeleteKeyPolicy handles xkms.deleteKeyPolicy.
func (s *Server) handleDeleteKeyPolicy(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return keyVersionCall(s, ctx, req, setKeyManagementTenant, keyManagementKeyID, s.xkmsService.DeleteKeyPolicy)
}

// handleSetKeyRotationPolicy handles xkms.setKeyRotationPolicy.
func (s *Server) handleSetKeyRotationPolicy(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return keyVersionCall(s, ctx, req, setRotationTenant, rotationKeyID, s.xkmsService.SetKeyRotationPolicy)
}

// handleGetKeyRotationPolicy handles xkms.getKeyRotationPolicy.
func (s *Server) handleGetKeyRotationPolicy(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return keyVersionCall(s, ctx, req, setKeyManagementTenant, keyManagementKeyID, s.xkmsService.GetKeyRotationPolicy)
}

// handleDeleteKeyRotationPolicy handles xkms.deleteKeyRotationPolicy.
func (s *Server) handleDeleteKeyRotationPolicy(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return keyVersionCall(s, ctx, req, setKeyManagementTenant, keyManagementKeyID, s.xkmsService.DeleteKeyRotationPolicy)
}

// handleGetSupportedAlgorithms handles xkms.getSupportedAlgorithms.
func (s *Server) handleGetSupportedAlgorithms(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return tenantCall(s, ctx, req, setBackendTenant, s.xkmsService.GetSupportedAlgorithms)
}

// handleBackendStatus handles xkms.backendStatus.
func (s *Server) handleBackendStatus(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return tenantCall(s, ctx, req, setBackendTenant, s.xkmsService.BackendStatus)
}

// handleBackendTest handles xkms.backendTest.
func (s *Server) handleBackendTest(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return tenantCall(s, ctx, req, setBackendTenant, s.xkmsService.BackendTest)
}

// handleSetKeySafety handles xkms.setKeySafety.
func (s *Server) handleSetKeySafety(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return keyVersionCall(s, ctx, req, setSafetyTenant, safetyKeyID, s.xkmsService.SetKeySafety)
}

// handleClearKeySafety handles xkms.clearKeySafety.
func (s *Server) handleClearKeySafety(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return keyVersionCall(s, ctx, req, setKeyManagementTenant, keyManagementKeyID, s.xkmsService.ClearKeySafety)
}

// handleSafetyCheck handles xkms.safetyCheck.
func (s *Server) handleSafetyCheck(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return tenantCall(s, ctx, req, setSafetyCheckTenant, s.xkmsService.SafetyCheck)
}

// handleSafetyReport handles xkms.safetyReport.
func (s *Server) handleSafetyReport(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return tenantCall(s, ctx, req, setSafetyReportTenant, s.xkmsService.SafetyReport)
}
