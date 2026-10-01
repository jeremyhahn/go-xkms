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
)

// The oidc.credential.* handlers are the MCP server side of the server-side
// OIDC credential API (pkg/oidc/credential). Each decodes its parameters --
// the fields of the transport request -- and delegates to XKMSService, whose
// credential service binds the caller's tenant and keeps a personal
// credential to its owner; they gate on the oidc_credentials:* pairs in
// authz.go's methodPermissions.

// oidcCredentialCall decodes a P from req and runs call with it, mapping its
// error through the OIDC credential classification.
func oidcCredentialCall[P, R any](s *Server, ctx context.Context, req *JSONRPCRequest, op string, call func(context.Context, *P) (R, error)) (interface{}, error) {
	return servicerCall(s, ctx, req, op, mapOIDCCredentialError, call)
}

// handleOIDCCredentialCreate handles oidc.credential.create.
func (s *Server) handleOIDCCredentialCreate(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return oidcCredentialCall(s, ctx, req, "oidc credential create", s.xkmsService.OIDCCredentialCreate)
}

// handleOIDCCredentialImport handles oidc.credential.import.
func (s *Server) handleOIDCCredentialImport(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return oidcCredentialCall(s, ctx, req, "oidc credential import", s.xkmsService.OIDCCredentialImport)
}

// handleOIDCCredentialGet handles oidc.credential.get.
func (s *Server) handleOIDCCredentialGet(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return oidcCredentialCall(s, ctx, req, "oidc credential get", s.xkmsService.OIDCCredentialGet)
}

// handleOIDCCredentialList handles oidc.credential.list.
func (s *Server) handleOIDCCredentialList(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return oidcCredentialCall(s, ctx, req, "oidc credential list", s.xkmsService.OIDCCredentialList)
}

// handleOIDCCredentialDelete handles oidc.credential.delete, answering with
// the deleted credential's reference.
func (s *Server) handleOIDCCredentialDelete(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return oidcCredentialCall(s, ctx, req, "oidc credential delete", func(ctx context.Context, params *transport.OIDCCredentialRef) (*transport.OIDCCredentialRef, error) {
		if err := s.xkmsService.OIDCCredentialDelete(ctx, params); err != nil {
			return nil, err
		}
		return params, nil
	})
}

// handleOIDCCredentialRefresh handles oidc.credential.refresh.
func (s *Server) handleOIDCCredentialRefresh(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return oidcCredentialCall(s, ctx, req, "oidc credential refresh", s.xkmsService.OIDCCredentialRefresh)
}

// handleOIDCCredentialToken handles oidc.credential.token.
func (s *Server) handleOIDCCredentialToken(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return oidcCredentialCall(s, ctx, req, "oidc credential token", s.xkmsService.OIDCCredentialGetAccessToken)
}

// handleOIDCCredentialDeviceStart handles oidc.credential.device.start.
func (s *Server) handleOIDCCredentialDeviceStart(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return oidcCredentialCall(s, ctx, req, "oidc credential device start", s.xkmsService.OIDCCredentialDeviceStart)
}

// handleOIDCCredentialDevicePoll handles oidc.credential.device.poll.
func (s *Server) handleOIDCCredentialDevicePoll(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return oidcCredentialCall(s, ctx, req, "oidc credential device poll", s.xkmsService.OIDCCredentialDevicePoll)
}
