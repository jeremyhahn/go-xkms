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

// The xkms.*KeyVersion* and xkms.rotateScopeKeys handlers are the MCP server
// side of the key-version API. Each decodes its parameters into the transport
// request and delegates to XKMSService; they gate on the keys:* pairs in
// server.go's rpcMethods table. The per-key operations act in the caller's
// tenant whatever the parameters say; xkms.rotateScopeKeys passes the
// requested tenant to the service, which binds it to the caller.

// keyVersionCall decodes a P from req, stamps the caller's tenant on it with
// setTenant, and runs call with it, mapping its error through the
// key-operation classification.
func keyVersionCall[P, R any](s *Server, ctx context.Context, req *JSONRPCRequest, setTenant func(*P, string), keyID func(*P) string, call func(context.Context, *P) (R, error)) (interface{}, error) {
	if s.xkmsService == nil {
		return nil, mapKeyOpError(xkms.ErrNotInitialized)
	}
	var params P
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}
	if keyID(&params) == "" {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: "key_id is required"}}
	}
	setTenant(&params, callerTenantID(ctx))
	resp, err := call(ctx, &params)
	if err != nil {
		return nil, mapKeyOpError(err)
	}
	return resp, nil
}

// The per-request tenant and key ID accessors keyVersionCall needs.
func setListTenant(p *transport.ListKeyVersionsRequest, tenant string) { p.TenantID = tenant }
func listKeyID(p *transport.ListKeyVersionsRequest) string             { return p.KeyID }
func setVersionTenant(p *transport.KeyVersionRequest, tenant string)   { p.TenantID = tenant }
func versionKeyID(p *transport.KeyVersionRequest) string               { return p.KeyID }
func setAllTenant(p *transport.AllKeyVersionsRequest, tenant string)   { p.TenantID = tenant }
func allKeyID(p *transport.AllKeyVersionsRequest) string               { return p.KeyID }

// handleListKeyVersions handles xkms.listKeyVersions.
func (s *Server) handleListKeyVersions(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return keyVersionCall(s, ctx, req, setListTenant, listKeyID, s.xkmsService.ListKeyVersions)
}

// handleEnableKeyVersion handles xkms.enableKeyVersion.
func (s *Server) handleEnableKeyVersion(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return keyVersionCall(s, ctx, req, setVersionTenant, versionKeyID, s.xkmsService.EnableKeyVersion)
}

// handleDisableKeyVersion handles xkms.disableKeyVersion.
func (s *Server) handleDisableKeyVersion(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return keyVersionCall(s, ctx, req, setVersionTenant, versionKeyID, s.xkmsService.DisableKeyVersion)
}

// handleRetireKeyVersion handles xkms.retireKeyVersion.
func (s *Server) handleRetireKeyVersion(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return keyVersionCall(s, ctx, req, setVersionTenant, versionKeyID, s.xkmsService.RetireKeyVersion)
}

// handleEnableAllKeyVersions handles xkms.enableAllKeyVersions.
func (s *Server) handleEnableAllKeyVersions(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return keyVersionCall(s, ctx, req, setAllTenant, allKeyID, s.xkmsService.EnableAllKeyVersions)
}

// handleDisableAllKeyVersions handles xkms.disableAllKeyVersions.
func (s *Server) handleDisableAllKeyVersions(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return keyVersionCall(s, ctx, req, setAllTenant, allKeyID, s.xkmsService.DisableAllKeyVersions)
}

// handleRotateScopeKeys handles xkms.rotateScopeKeys. Its parameters are
// optional: without them the caller's own tenant is rotated.
func (s *Server) handleRotateScopeKeys(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	if s.xkmsService == nil {
		return nil, mapKeyOpError(xkms.ErrNotInitialized)
	}
	var params transport.RotateScopeKeysRequest
	if len(req.Params) > 0 {
		if err := decodeParams(req, &params); err != nil {
			return nil, err
		}
	}
	resp, err := s.xkmsService.RotateScopeKeys(ctx, &params)
	if err != nil {
		return nil, mapKeyOpError(err)
	}
	return resp, nil
}
