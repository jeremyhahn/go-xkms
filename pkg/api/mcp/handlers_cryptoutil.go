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
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// The crypto utility handlers decode the params, scope a keyed request to
// the caller's tenant and hand it to the service; keyVersionCall maps the
// service's errors through the key-operation classification.

// The per-request tenant and key ID accessors keyVersionCall needs.
func setRewrapTenant(p *transport.RewrapRequest, tenant string) {
	if p.Source != nil {
		p.Source.TenantID = tenant
	}
}

func rewrapKeyID(p *transport.RewrapRequest) string {
	if p.Source == nil {
		return ""
	}
	return p.Source.KeyID
}

func setEncryptBatchTenant(p *transport.EncryptBatchRequest, tenant string) { p.TenantID = tenant }
func encryptBatchKeyID(p *transport.EncryptBatchRequest) string             { return p.KeyID }
func setDecryptBatchTenant(p *transport.DecryptBatchRequest, tenant string) { p.TenantID = tenant }
func decryptBatchKeyID(p *transport.DecryptBatchRequest) string             { return p.KeyID }
func setDataKeyTenant(p *transport.GenerateDataKeyRequest, tenant string)   { p.TenantID = tenant }
func dataKeyKeyID(p *transport.GenerateDataKeyRequest) string               { return p.KeyID }
func setHMACTenant(p *transport.GenerateHMACRequest, tenant string)         { p.TenantID = tenant }
func hmacKeyID(p *transport.GenerateHMACRequest) string                     { return p.KeyID }
func setVerifyHMACTenant(p *transport.VerifyHMACRequest, tenant string)     { p.TenantID = tenant }
func verifyHMACKeyID(p *transport.VerifyHMACRequest) string                 { return p.KeyID }

// handleRewrap handles xkms.rewrap.
func (s *Server) handleRewrap(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return keyVersionCall(s, ctx, req, setRewrapTenant, rewrapKeyID, s.xkmsService.Rewrap)
}

// handleEncryptBatch handles xkms.encryptBatch.
func (s *Server) handleEncryptBatch(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return keyVersionCall(s, ctx, req, setEncryptBatchTenant, encryptBatchKeyID, s.xkmsService.EncryptBatch)
}

// handleDecryptBatch handles xkms.decryptBatch.
func (s *Server) handleDecryptBatch(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return keyVersionCall(s, ctx, req, setDecryptBatchTenant, decryptBatchKeyID, s.xkmsService.DecryptBatch)
}

// handleGenerateDataKey handles xkms.generateDataKey.
func (s *Server) handleGenerateDataKey(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return keyVersionCall(s, ctx, req, setDataKeyTenant, dataKeyKeyID, s.xkmsService.GenerateDataKey)
}

// handleGenerateWrappedDataKey handles xkms.generateWrappedDataKey.
func (s *Server) handleGenerateWrappedDataKey(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return keyVersionCall(s, ctx, req, setDataKeyTenant, dataKeyKeyID, s.xkmsService.GenerateWrappedDataKey)
}

// handleGenerateHMAC handles xkms.generateHMAC.
func (s *Server) handleGenerateHMAC(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return keyVersionCall(s, ctx, req, setHMACTenant, hmacKeyID, s.xkmsService.GenerateHMAC)
}

// handleVerifyHMAC handles xkms.verifyHMAC.
func (s *Server) handleVerifyHMAC(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return keyVersionCall(s, ctx, req, setVerifyHMACTenant, verifyHMACKeyID, s.xkmsService.VerifyHMAC)
}

// keylessCall decodes the params of a request that names no key and runs
// call with them, mapping its error through the key-operation
// classification.
func keylessCall[P, R any](s *Server, ctx context.Context, req *JSONRPCRequest, call func(context.Context, *P) (R, error)) (interface{}, error) {
	if s.xkmsService == nil {
		return nil, mapKeyOpError(xkms.ErrNotInitialized)
	}
	var params P
	if len(req.Params) == 0 {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: "params are required"}}
	}
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}
	resp, err := call(ctx, &params)
	if err != nil {
		return nil, mapKeyOpError(err)
	}
	return resp, nil
}

// handleGenerateRandom handles xkms.generateRandom.
func (s *Server) handleGenerateRandom(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return keylessCall(s, ctx, req, s.xkmsService.GenerateRandom)
}

// handleHash handles xkms.hash.
func (s *Server) handleHash(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return keylessCall(s, ctx, req, s.xkmsService.Hash)
}
